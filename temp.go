package connectivity

import (
	"fmt"
	"reflect"
	"strings"

	"bitbucket.it.keysight.com/isgappsec/mantisshrimp/go/cmd/wireless-data-model/generated/mwapi"
	"bitbucket.it.keysight.com/isgappsec/mantisshrimp/go/cmd/wireless-data-model/helpers"
	"bitbucket.it.keysight.com/isgappsec/mantisshrimp/go/cmd/wireless-data-model/nodes/config"
	"bitbucket.it.keysight.com/isgappsec/mantisshrimp/go/cmd/wireless-data-model/rest/model"
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
	peerNodeTypes       []mwapi.LCNodeType
}

func newNodeConnectionsInfo(
	nodeType mwapi.LCNodeType,
	peerConnsInfo []*peerConnectionInfo,
) *nodeConnectionsInfo {
	peerNodeTypes := make([]mwapi.LCNodeType, 0, len(peerConnsInfo))
	for _, peerConnInfo := range peerConnsInfo {
		peerNodeTypes = append(peerNodeTypes, peerConnInfo.peerNodeType)
	}
	return &nodeConnectionsInfo{
		nodeType:            nodeType,
		peerConnectionsInfo: peerConnsInfo,
		peerNodeTypes:       peerNodeTypes,
	}
}

// A GraphBuilder is used to build a connectivity graph.
type GraphBuilder struct {
	topology        model.WirelessConfigType
	logger          *logging.Logger
	config          interface{}
	configsProvider config.DistributedNodeConfigsProvider
	graph           *Graph
}

// NewGraphBuilder creates a new connectivity graph builder.
func NewGraphBuilder(topology model.WirelessConfigType, logger *logging.Logger) *GraphBuilder {
	return &GraphBuilder{
		topology: topology,
		logger:   logger,
		graph:    newGraph(logger),
	}
}

// Setup prepare the graph builder for usage.
// The 'config' parameter keeps the global configuration and is used to access the DUT nodes.
// The 'configsProvider' is used to access the agent distributed nodes and
// their peers.
func (gb *GraphBuilder) Setup(
	config interface{},
	configsProvider config.DistributedNodeConfigsProvider,
) {
	gb.config = config
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
	return gb.getNodeFromConfig(peerNodeType)
}

func (gb *GraphBuilder) getNodeFromConfig(nodeType mwapi.LCNodeType) (*config.NodeConfig, error) {
	configVal := reflect.ValueOf(gb.config)
	if configVal.Kind() == reflect.Ptr {
		configVal = reflect.Indirect(configVal)
	}
	nodeFieldName := fmt.Sprintf("Nodes.%s", strings.Title(strings.ToLower(string(nodeType))))

	nodeVal := helpers.FieldByName(configVal, nodeFieldName)
	if !nodeVal.IsValid() {
		return nil, fmt.Errorf("invalid field %s in config", nodeFieldName)
	}
	nodeConfig := &config.NodeConfig{
		AgentID: dutKey,
		Config:  nodeVal.Interface(),
	}
	return nodeConfig, nil
}

func (gb *GraphBuilder) getDUTNodeConfig(nodeType mwapi.LCNodeType) (*config.NodeConfig, error) {
	nodeConfig, err := gb.getNodeFromConfig(nodeType)
	if err != nil {
		return nil, err
	}
	nodeRanges := helpers.GetEnabledNodeRanges(nodeConfig.Config)
	if !helpers.AllEnabledRangesAreDUT(nodeRanges) {
		return nil, nil
	}
	return nodeConfig, nil
}

func (gb *GraphBuilder) connectNodeToPeers(connsInfo *nodeConnectionsInfo) error {
	nodeConfigs, err := gb.getNodeConfigs(connsInfo.nodeType)
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
			err = gb.connectDUTNodeToPeers(nodeConfig.AgentID, nodeRanges, connsInfo)
		} else {
			err = gb.connectDistribNodeToPeers(nodeConfig.AgentID, nodeRanges, connsInfo)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (gb *GraphBuilder) connectDistribNodeToPeers(
	nodeAgentID string,
	nodeRanges []interface{},
	connsInfo *nodeConnectionsInfo,
) error {
	peerNodeConfigs, err := gb.getPeerNodeConfigs(nodeAgentID, connsInfo.nodeType,
		connsInfo.peerNodeTypes)
	if err != nil {
		return err
	}
	if len(peerNodeConfigs) == 0 {
		return nil
	}
	return gb.doConnectNodeToPeers(nodeAgentID, nodeRanges, peerNodeConfigs, connsInfo)
}

func (gb *GraphBuilder) connectDUTNodeToPeers(
	nodeAgentID string,
	nodeRanges []interface{},
	connsInfo *nodeConnectionsInfo,
) error {
	peerMap := make(map[mwapi.LCNodeType][]config.NodeConfig)
	for _, peerNodeType := range connsInfo.peerNodeTypes {
		peerNodeConfigs, err := gb.getNodeConfigs(peerNodeType)
		if err != nil {
			return err
		}
		peerMap[peerNodeType] = peerNodeConfigs
	}
	return gb.doConnectNodeToPeers(nodeAgentID, nodeRanges, peerMap, connsInfo)
}

func (gb *GraphBuilder) doConnectNodeToPeers(
	nodeAgentID string,
	nodeRanges []interface{},
	peerMap map[mwapi.LCNodeType][]config.NodeConfig,
	connsInfo *nodeConnectionsInfo,
) error {
	for i := range nodeRanges {
		for _, peerConnInfo := range connsInfo.peerConnectionsInfo {
			err := gb.doConnectNodeRangeToPeer(connsInfo.nodeType, nodeAgentID, nodeRanges[i],
				peerMap, peerConnInfo)
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
			connected, err := gb.doConnectNodeRangeToPeerRange(nodeType, nodeAgentID, nodeRange,
				peerDistribNode.AgentID, peerRanges[i], peerConnInfo)
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

	agentIntf := &AgentNodeInterface{
		AgentID:       nodeAgentID,
		NodeType:      nodeType,
		InterfaceType: peerConnInfo.nodeIntf,
	}
	peerAgentIntf := &AgentNodeInterface{
		AgentID:       peerAgentID,
		NodeType:      peerConnInfo.peerNodeType,
		InterfaceType: peerConnInfo.peerNodeIntf,
	}

	switch remotePeerIDVal.Kind() {
	case reflect.String:
		if remotePeerIDVal.String() == peerID {
			err := gb.graph.addConnectionForRanges(agentIntf, nodeRange, peerAgentIntf, peerRange)
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
					agentIntf, nodeRange, peerAgentIntf, peerRange,
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
