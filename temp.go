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
	logger *logging.Logger
	graph  *Graph
}

// NewGraphBuilder creates a new connectivity graph builder.
func NewGraphBuilder(logger *logging.Logger) *GraphBuilder {
	return &GraphBuilder{
		logger: logger,
		graph:  newGraph(logger),
	}
}

// GetGraph is used to get the constructed connectivity graph.
func (gb *GraphBuilder) GetGraph() *Graph {
	return gb.graph
}

// BuildGraph is used to build the connectivity graph given a topology
// node type.
// The 'globalConfig' parameter keeps the global configuration
// (mwapi.Config/mwapi.SbaConfig/mwapi.UpfIsolationConfig) and is used to
// access the DUT nodes.
// The 'configsProvider' is used to access the agent distributed nodes and
// their peers.
func (gb *GraphBuilder) BuildGraph(
	topologyNodeType mwapi.LCNodeType,
	globalConfig interface{},
	configsProvider config.DistributedNodeConfigsProvider,
) error {
	switch topologyNodeType {
	case mwapi.AMF:
		return gb.buildAMFGraph(globalConfig, configsProvider)
	case mwapi.AUSF:
		return gb.buildAUSFGraph(globalConfig, configsProvider)
	case mwapi.PCF:
		return gb.buildPCFGraph(globalConfig, configsProvider)
	case mwapi.RAN:
		return gb.buildRANGraph(globalConfig, configsProvider)
	case mwapi.SMF:
		return gb.buildSMFGraph(globalConfig, configsProvider)
	}
	return nil
}

// ClearGraph clears the content of the constructed connectivity graph.
func (gb *GraphBuilder) ClearGraph() {
	gb.graph.clear()
}

// Get the configs for nodes of a given type (both the distributed and the
// DUT node configs).
func (gb *GraphBuilder) getNodeConfigs(
	nodeType mwapi.LCNodeType,
	globalConfig interface{},
	configsProvider config.DistributedNodeConfigsProvider,
) ([]config.NodeConfig, error) {
	nodeConfigs := configsProvider.GetDistributedNodeConfigs(nodeType)
	dutNodeConfig, err := gb.getDUTNodeConfig(nodeType, globalConfig)
	if err != nil {
		return nil, err
	}
	if dutNodeConfig != nil {
		nodeConfigs = append(nodeConfigs, *dutNodeConfig)
	}
	return nodeConfigs, nil
}

// Get the peer configs of a distributed node.
// Both distributed and DUT peers are returned.
func (gb *GraphBuilder) getPeerNodeConfigs(
	agentID string,
	nodeType mwapi.LCNodeType,
	peerNodeTypes []mwapi.LCNodeType,
	globalConfig interface{},
	configsProvider config.DistributedNodeConfigsProvider,
) (map[mwapi.LCNodeType][]config.NodeConfig, error) {
	peerNodeConfigs := make(map[mwapi.LCNodeType][]config.NodeConfig)
	for _, peerNodeType := range peerNodeTypes {
		peerNodeConfig, err := gb.getPeerNodeConfig(
			agentID, nodeType, peerNodeType, globalConfig, configsProvider)
		if err != nil {
			return nil, err
		}
		if peerNodeConfig != nil {
			peerNodeConfigs[peerNodeType] =
				[]config.NodeConfig{*peerNodeConfig}
		}
	}
	return peerNodeConfigs, nil
}

// Get the config of a peer node (either using the config provider or the
// global config).
func (gb *GraphBuilder) getPeerNodeConfig(
	agentID string,
	nodeType mwapi.LCNodeType,
	peerNodeType mwapi.LCNodeType,
	globalConfig interface{},
	configsProvider config.DistributedNodeConfigsProvider,
) (*config.NodeConfig, error) {
	distribPeerNodeConfig := configsProvider.GetDistributedPeerNodeConfig(
		agentID, nodeType, peerNodeType)
	if distribPeerNodeConfig != nil {
		return distribPeerNodeConfig, nil
	}
	return gb.getDUTNodeConfig(peerNodeType, globalConfig)
}

// Get the config of a DUT node from global config.
func (gb *GraphBuilder) getDUTNodeConfig(
	nodeType mwapi.LCNodeType,
	globalConfig interface{},
) (*config.NodeConfig, error) {
	globalConfigValue := reflect.ValueOf(globalConfig)
	if globalConfigValue.Kind() == reflect.Ptr {
		globalConfigValue = reflect.Indirect(globalConfigValue)
	}
	nodeFieldName := fmt.Sprintf("Nodes.%s",
		strings.Title(strings.ToLower(string(nodeType))))

	nodeValue := helpers.FieldByName(globalConfigValue, nodeFieldName)

	if !nodeValue.IsValid() {
		return nil, fmt.Errorf(
			"invalid field %s in global config", nodeFieldName)
	}

	nodeRangesValue := nodeValue.FieldByName("Ranges")
	if !nodeRangesValue.IsValid() {
		return nil, fmt.Errorf(
			"invalid field %s.Ranges in global config", nodeFieldName)
	}

	nodeRanges := nodeRangesValue.Interface()
	if !helpers.AtLeastOneRangeEnabled(nodeRanges) ||
		!helpers.AllEnabledRangesAreDUT(nodeRanges) {
		return nil, nil
	}

	nodeConfig := &config.NodeConfig{
		AgentID: dutKey,
		Config:  nodeValue.Interface(),
	}

	return nodeConfig, nil
}

// Connect a node to its peers.
func (gb *GraphBuilder) connectNodeToPeers(
	globalConfig interface{},
	configsProvider config.DistributedNodeConfigsProvider,
	nodeConnsInfo *nodeConnectionsInfo,
) error {
	nodeConfigs, err := gb.getNodeConfigs(nodeConnsInfo.nodeType, globalConfig,
		configsProvider)

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
		if helpers.AllRangesAreDUT(nodeRanges) {
			err = gb.connectDUTNodeToPeers(nodeConfig.AgentID, nodeRanges,
				globalConfig, configsProvider, nodeConnsInfo)
		} else {
			err = gb.connectDistributedNodeToPeers(nodeConfig.AgentID,
				nodeRanges, globalConfig, configsProvider, nodeConnsInfo)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// Connect a distributed node to its peers.
func (gb *GraphBuilder) connectDistributedNodeToPeers(
	nodeAgentID string,
	nodeRanges []interface{},
	globalConfig interface{},
	configsProvider config.DistributedNodeConfigsProvider,
	nodeConnsInfo *nodeConnectionsInfo,
) error {
	peerNodeConfigs, err := gb.getPeerNodeConfigs(
		nodeAgentID,
		nodeConnsInfo.nodeType,
		nodeConnsInfo.getPeerNodeTypes(),
		globalConfig,
		configsProvider,
	)
	if err != nil {
		return err
	}
	if len(peerNodeConfigs) == 0 {
		return nil
	}
	return gb.doConnectNodeToPeers(nodeAgentID, nodeRanges,
		peerNodeConfigs, nodeConnsInfo)
}

// Connect a DUT node to its peers.
func (gb *GraphBuilder) connectDUTNodeToPeers(
	nodeAgentID string,
	nodeRanges []interface{},
	globalConfig interface{},
	configsProvider config.DistributedNodeConfigsProvider,
	nodeConnsInfo *nodeConnectionsInfo,
) error {
	peerMap := make(map[mwapi.LCNodeType][]config.NodeConfig)
	peerNodeTypes := nodeConnsInfo.getPeerNodeTypes()
	for _, peerNodeType := range peerNodeTypes {
		peerNodeConfigs, err := gb.getNodeConfigs(
			peerNodeType, globalConfig, configsProvider)
		if err != nil {
			return err
		}
		peerMap[peerNodeType] = peerNodeConfigs
	}

	return gb.doConnectNodeToPeers(nodeAgentID, nodeRanges, peerMap,
		nodeConnsInfo)
}

func (gb *GraphBuilder) doConnectNodeToPeers(
	nodeAgentID string,
	nodeRanges []interface{},
	peerMap map[mwapi.LCNodeType][]config.NodeConfig,
	nodeConnsInfo *nodeConnectionsInfo,
) error {
	for i := range nodeRanges {
		for _, peerConnInfo := range nodeConnsInfo.peerConnectionsInfo {
			err := gb.doConnectNodeRangeToPeer(nodeConnsInfo.nodeType,
				nodeAgentID, nodeRanges[i], peerMap,
				peerConnInfo)

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
			connected, err := gb.tryConnectNodeRangeToPeerRange(
				nodeType, nodeAgentID, nodeRange, peerDistribNode.AgentID,
				peerRanges[i], peerConnInfo)

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

func (gb *GraphBuilder) tryConnectNodeRangeToPeerRange(
	nodeType mwapi.LCNodeType,
	nodeAgentID string,
	nodeRange interface{},
	peerAgentID string,
	peerRange interface{},
	peerConnInfo *peerConnectionInfo,
) (bool, error) {
	remotePeerIDVal := helpers.FieldByName(
		reflect.ValueOf(nodeRange),
		peerConnInfo.nodeRangePeerIDPath)

	if !remotePeerIDVal.IsValid() {
		return false, fmt.Errorf("invalid field %s",
			peerConnInfo.nodeRangePeerIDPath)
	}

	peerIDVal := helpers.FieldByName(reflect.ValueOf(peerRange), rangeIDPath)

	if !peerIDVal.IsValid() || peerIDVal.Kind() != reflect.String {
		return false, fmt.Errorf("invalid field %s", rangeIDPath)
	}

	peerID := peerIDVal.String()

	switch remotePeerIDVal.Kind() {
	case reflect.String:
		if remotePeerIDVal.String() == peerID {
			err := gb.graph.addConnectionForRanges(
				nodeAgentID, nodeType, peerConnInfo.nodeIntf, nodeRange,
				peerAgentID, peerConnInfo.peerNodeType,
				peerConnInfo.peerNodeIntf, peerRange,
			)
			if err != nil {
				return false, err
			}
			return true, nil
		}
	case reflect.Slice:
		for i := 0; i < remotePeerIDVal.Len(); i++ {
			if remotePeerIDVal.Index(i).Kind() != reflect.String {
				return false,
					fmt.Errorf("invalid value at index %d for field %s",
						i, peerConnInfo.nodeRangePeerIDPath)
			}
			if remotePeerIDVal.Index(i).String() == peerID {
				err := gb.graph.addConnectionForRanges(
					nodeAgentID, nodeType, peerConnInfo.nodeIntf, nodeRange,
					peerAgentID, peerConnInfo.peerNodeType,
					peerConnInfo.peerNodeIntf, peerRange,
				)
				if err != nil {
					return false, err
				}
				return true, nil
			}
		}
	default:
		return false, fmt.Errorf("invalid field %s",
			peerConnInfo.nodeRangePeerIDPath)
	}

	return false, nil
}
