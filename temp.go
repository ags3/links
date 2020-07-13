package connectivity

import (
	"fmt"
	"reflect"
	"strings"

	"bitbucket.it.keysight.com/isgappsec/mantisshrimp/go/cmd/wireless-data-model/generated/mwapi"
	"bitbucket.it.keysight.com/isgappsec/mantisshrimp/go/cmd/wireless-data-model/helpers"
	"bitbucket.it.keysight.com/isgappsec/mantisshrimp/go/cmd/wireless-data-model/nodes/config"
	"bitbucket.it.keysight.com/isgappsec/mantisshrimp/go/lib/logging"
)

const (
	dutKey      = "DUT"
	rangeIDPath = "Id"
)

// Keeps information about a node connection to a specific peer.
type peerConnectionInfo struct {
	nodeIntf            string
	nodeRangePeerIDPath string
	peerNodeType        mwapi.LCNodeType
	peerNodeIntf        string
}

// Keeps information about all possible connections a node can have to
// its peers.
type nodeConnectionsInfo struct {
	nodeType            mwapi.LCNodeType
	peerConnectionsInfo []*peerConnectionInfo
}

func (nc *nodeConnectionsInfo) getPeerNodeTypes() []mwapi.LCNodeType {
	peerNodeTypes := make([]mwapi.LCNodeType, 0, len(nc.peerConnectionsInfo))
	for _, peerConnInfo := range nc.peerConnectionsInfo {
		peerNodeTypes = append(peerNodeTypes, peerConnInfo.peerNodeType)
	}
	return peerNodeTypes
}

// A GraphBuilder is used to build a connectivity graph.
type GraphBuilder struct {
	logger          *logging.Logger
	globalConfig    interface{}
	configsProvider config.DistributedNodeConfigsProvider
	graph           *Graph
}

// NewGraphBuilder creates a new connectivity graph builder.
func NewGraphBuilder(logger *logging.Logger) *GraphBuilder {
	return &GraphBuilder{
		logger: logger,
		graph:  newGraph(logger),
	}
}

// Setup prepare the graph builder for usage.
// The 'globalConfig' parameter keeps the global configuration
// (mwapi.Config/mwapi.SbaConfig/mwapi.UpfIsolationConfig) and is used to
// access the DUT nodes.
// The 'configsProvider' is used to access the agent distributed nodes and
// their peers.
func (gb *GraphBuilder) Setup(
	globalConfig interface{},
	configsProvider config.DistributedNodeConfigsProvider,
) {
	gb.globalConfig = globalConfig
	gb.configsProvider = configsProvider
	gb.graph.clear()
}

// GetGraph is used to get the constructed connectivity graph.
func (gb *GraphBuilder) GetGraph() *Graph {
	return gb.graph
}

// BuildGraph is used to build the connectivity graph given a topology
// node type.
func (gb *GraphBuilder) BuildGraph(nodeType mwapi.LCNodeType) error {
	switch nodeType {
	case mwapi.AMF:
		return gb.buildAMFGraph()
	case mwapi.AUSF:
		return gb.buildAUSFGraph()
	case mwapi.PCF:
		return gb.buildPCFGraph()
	case mwapi.RAN:
		return gb.buildRANGraph()
	case mwapi.SMF:
		return gb.buildSMFGraph()
	}
	return nil
}

func (gb *GraphBuilder) getNodeConfigs(nodeType mwapi.LCNodeType) ([]config.NodeConfig, error) {
	nodeConfigs := gb.configsProvider.GetDistributedNodeConfigs(nodeType)
	dutNodeConfig, err := gb.getDUTNodeConfig(nodeType)
	if err != nil {
		return nil, err
	}
	if dutNodeConfig != nil {
		nodeConfigs = append(nodeConfigs, *dutNodeConfig)
	}
	return nodeConfigs, nil
}

func (gb *GraphBuilder) getPeerNodeConfigs(
	agentID string,
	nodeType mwapi.LCNodeType,
	peerNodeTypes []mwapi.LCNodeType,
) (map[mwapi.LCNodeType][]config.NodeConfig, error) {
	peerNodeConfigs := make(map[mwapi.LCNodeType][]config.NodeConfig)
	for _, peerNodeType := range peerNodeTypes {
		peerNodeConfig, err := gb.getPeerNodeConfig(agentID, nodeType, peerNodeType)
		if err != nil {
			return nil, err
		}
		if peerNodeConfig != nil {
			peerNodeConfigs[peerNodeType] = []config.NodeConfig{*peerNodeConfig}
		}
	}
	return peerNodeConfigs, nil
}

func (gb *GraphBuilder) getPeerNodeConfig(
	agentID string,
	nodeType mwapi.LCNodeType,
	peerNodeType mwapi.LCNodeType,
) (*config.NodeConfig, error) {
	nodeConfig := gb.configsProvider.GetDistributedPeerNodeConfig(agentID, nodeType, peerNodeType)
	if nodeConfig != nil {
		return nodeConfig, nil
	}
	return gb.getDUTNodeConfig(peerNodeType)
}

func (gb *GraphBuilder) getDUTNodeConfig(nodeType mwapi.LCNodeType) (*config.NodeConfig, error) {
	globalConfigValue := reflect.ValueOf(gb.globalConfig)
	if globalConfigValue.Kind() == reflect.Ptr {
		globalConfigValue = reflect.Indirect(globalConfigValue)
	}
	nodeFieldName := fmt.Sprintf("Nodes.%s", strings.Title(strings.ToLower(string(nodeType))))

	nodeValue := helpers.FieldByName(globalConfigValue, nodeFieldName)
	if !nodeValue.IsValid() {
		return nil, fmt.Errorf("invalid field %s in config", nodeFieldName)
	}
	nodeRangesValue := nodeValue.FieldByName("Ranges")
	if !nodeRangesValue.IsValid() {
		return nil, fmt.Errorf("invalid field %s.Ranges in config", nodeFieldName)
	}
	nodeRanges := nodeRangesValue.Interface()
	if !helpers.AtLeastOneRangeEnabled(nodeRanges) || !helpers.AllEnabledRangesAreDUT(nodeRanges) {
		return nil, nil
	}
	nodeConfig := &config.NodeConfig{
		AgentID: dutKey,
		Config:  nodeValue.Interface(),
	}
	return nodeConfig, nil
}

func (gb *GraphBuilder) connectNodeToPeers(nodeConnsInfo *nodeConnectionsInfo) error {
	nodeConfigs, err := gb.getNodeConfigs(nodeConnsInfo.nodeType)
	if err != nil {
		return err
	}
	for i := range nodeConfigs {
		nodeConfig := &nodeConfigs[i]
		if !helpers.NodeEnabled(nodeConfig.Config) {
			continue
		}
		nodeRanges := helpers.GetEnabledNodeRanges(nodeConfig.Config)
		if len(nodeRanges) == 0 {
			continue
		}
		var err error
		if helpers.AllEnabledRangesAreDUT(nodeRanges) {
			err = gb.connectDUTNodeToPeers(nodeConfig.AgentID, nodeRanges, nodeConnsInfo)
		} else {
			err = gb.connectDistributedNodeToPeers(nodeConfig.AgentID, nodeRanges, nodeConnsInfo)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (gb *GraphBuilder) connectDistributedNodeToPeers(
	nodeAgentID string,
	nodeRanges []interface{},
	nodeConnsInfo *nodeConnectionsInfo,
) error {
	peerNodeConfigs, err := gb.getPeerNodeConfigs(
		nodeAgentID,
		nodeConnsInfo.nodeType,
		nodeConnsInfo.getPeerNodeTypes(),
	)
	if err != nil {
		return err
	}
	if len(peerNodeConfigs) == 0 {
		return nil
	}
	return gb.doConnectNodeToPeers(nodeAgentID, nodeRanges, peerNodeConfigs, nodeConnsInfo)
}

func (gb *GraphBuilder) connectDUTNodeToPeers(
	nodeAgentID string,
	nodeRanges []interface{},
	nodeConnsInfo *nodeConnectionsInfo,
) error {
	peerMap := make(map[mwapi.LCNodeType][]config.NodeConfig)
	peerNodeTypes := nodeConnsInfo.getPeerNodeTypes()
	for _, peerNodeType := range peerNodeTypes {
		peerNodeConfigs, err := gb.getNodeConfigs(peerNodeType)
		if err != nil {
			return err
		}
		peerMap[peerNodeType] = peerNodeConfigs
	}
	return gb.doConnectNodeToPeers(nodeAgentID, nodeRanges, peerMap, nodeConnsInfo)
}

func (gb *GraphBuilder) doConnectNodeToPeers(
	nodeAgentID string,
	nodeRanges []interface{},
	peerMap map[mwapi.LCNodeType][]config.NodeConfig,
	nodeConnsInfo *nodeConnectionsInfo,
) error {
	for i := range nodeRanges {
		for _, peerConnInfo := range nodeConnsInfo.peerConnectionsInfo {
			err := gb.doConnectNodeRangeToPeer(
				nodeConnsInfo.nodeType,
				nodeAgentID,
				nodeRanges[i],
				peerMap,
				peerConnInfo,
			)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (gb *GraphBuilder) doConnectNodeRangeToPeer(
	nodeType mwapi.LCNodeType,
	nodeAgentID string,
	nodeRange interface{},
	peerMap map[mwapi.LCNodeType][]config.NodeConfig,
	peerConnInfo *peerConnectionInfo,
) error {
	peerDistribNodes := peerMap[peerConnInfo.peerNodeType]
	for _, peerDistribNode := range peerDistribNodes {
		if !helpers.NodeEnabled(peerDistribNode.Config) {
			continue
		}
		peerRanges := helpers.GetEnabledNodeRanges(peerDistribNode.Config)
		for i := range peerRanges {
			connected, err := gb.doConnectNodeRangeToPeerRange(
				nodeType,
				nodeAgentID,
				nodeRange,
				peerDistribNode.AgentID,
				peerRanges[i],
				peerConnInfo,
			)
			if err != nil {
				return err
			}
			if connected {
				break
			}
		}
	}
	return nil
}

func (gb *GraphBuilder) doConnectNodeRangeToPeerRange(
	nodeType mwapi.LCNodeType,
	nodeAgentID string,
	nodeRange interface{},
	peerAgentID string,
	peerRange interface{},
	peerConnInfo *peerConnectionInfo,
) (bool, error) {
	remotePeerIDVal := helpers.FieldByName(
		reflect.ValueOf(nodeRange),
		peerConnInfo.nodeRangePeerIDPath,
	)
	if !remotePeerIDVal.IsValid() {
		return false, fmt.Errorf(
			"invalid field %s", peerConnInfo.nodeRangePeerIDPath,
		)
	}

	peerIDVal := helpers.FieldByName(reflect.ValueOf(peerRange), rangeIDPath)
	if !peerIDVal.IsValid() || peerIDVal.Kind() != reflect.String {
		return false, fmt.Errorf("invalid field %s", rangeIDPath)
	}
	peerID := peerIDVal.String()

	agentNodeIntf := &AgentNodeInterface{
		AgentID:       nodeAgentID,
		NodeType:      nodeType,
		InterfaceType: peerConnInfo.nodeIntf,
	}
	peerAgentNodeIntf := &AgentNodeInterface{
		AgentID:       peerAgentID,
		NodeType:      peerConnInfo.peerNodeType,
		InterfaceType: peerConnInfo.peerNodeIntf,
	}

	switch remotePeerIDVal.Kind() {
	case reflect.String:
		if remotePeerIDVal.String() == peerID {
			err := gb.graph.addConnectionForRanges(
				agentNodeIntf,
				nodeRange,
				peerAgentNodeIntf,
				peerRange,
			)
			if err != nil {
				return false, err
			}
			return true, nil
		}
	case reflect.Slice:
		for i := 0; i < remotePeerIDVal.Len(); i++ {
			if remotePeerIDVal.Index(i).Kind() != reflect.String {
				return false, fmt.Errorf(
					"invalid field %s[%d]", peerConnInfo.nodeRangePeerIDPath, i,
				)
			}
			if remotePeerIDVal.Index(i).String() == peerID {
				err := gb.graph.addConnectionForRanges(
					agentNodeIntf,
					nodeRange,
					peerAgentNodeIntf,
					peerRange,
				)
				if err != nil {
					return false, err
				}
				return true, nil
			}
		}
	default:
		return false, fmt.Errorf("invalid field %s", peerConnInfo.nodeRangePeerIDPath)
	}
	return false, nil
}
