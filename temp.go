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
	dutKey = "DUT"
)

// Keeps the name of the fields needed to access connection related data by reflection, for the
// source node and the destination (peer) node.
// Those fields are members in the node specific range structure.
type connectionDataFields struct {
	nodeRemotePeerID string
	nodeIPAddress    string
	nodeIPPrefix     string
	nodeGateway      string
	peerIPAddress    string
	peerIPPrefix     string
	peerGateway      string
}

// Keeps static configuration information about a specific connection between a source node and
// a destination (peer) node.
type connectionSpec struct {
	nodeType     mwapi.LCNodeType
	nodeIntf     string
	peerNodeType mwapi.LCNodeType
	peerNodeIntf string
	// An indirect connection means that we have a peer which is not a direct remote in config
	// (we don't have a remote peer ID in the source node config for it).
	// It means that it won't be found using the distributed node configs provider.
	// It also means that we won't use the remote peer ID when building connections to it.
	indirect bool
	fields   connectionDataFields
}

// Keeps static configuration information about all possible connections a node can have to
// its peers.
type nodeConnectionsSpec struct {
	nodeType      mwapi.LCNodeType
	peerNodeTypes []mwapi.LCNodeType
	connsSpec     []*connectionSpec
}

// A GraphBuilder is used to build a connectivity graph.
type GraphBuilder struct {
	topology        model.WirelessConfigType
	logger          *logging.Logger
	globalConfig    interface{}
	configsProvider config.DistributedNodeConfigsProvider
	graph           *Graph
}

func newNodeConnectionsSpec(nodeType mwapi.LCNodeType, connsSpec []*connectionSpec) *nodeConnectionsSpec {
	peerNodeTypes := make([]mwapi.LCNodeType, 0, len(connsSpec))
	for _, connSpec := range connsSpec {
		peerNodeTypes = append(peerNodeTypes, connSpec.peerNodeType)
	}
	return &nodeConnectionsSpec{
		nodeType:      nodeType,
		peerNodeTypes: peerNodeTypes,
		connsSpec:     connsSpec,
	}
}

// NewGraphBuilder creates a new connectivity graph builder.
func NewGraphBuilder(topology model.WirelessConfigType, logger *logging.Logger) *GraphBuilder {
	return &GraphBuilder{
		topology: topology,
		logger:   logger,
		graph:    newGraph(logger),
	}
}

// Setup prepares the graph builder for usage.
// The 'globalConfig' parameter keeps the global configuration and is used to access the DUT nodes.
// The 'configsProvider' is used to access the agent distributed nodes and their peers.
func (gb *GraphBuilder) Setup(globalConfig interface{}, configsProvider config.DistributedNodeConfigsProvider) {
	gb.globalConfig = globalConfig
	gb.configsProvider = configsProvider
	gb.graph.clear()
}

// GetGraph is used to get the constructed connectivity graph.
func (gb *GraphBuilder) GetGraph() *Graph {
	return gb.graph
}

// BuildGraph is used to build the connectivity graph given a topology node type.
func (gb *GraphBuilder) BuildGraph(nodeType mwapi.LCNodeType) error {
	// For the moment, only the full core topology is supported.
	if gb.topology != model.FullCore {
		return nil
	}
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
	case mwapi.UDM:
		return gb.buildUDMGraph()
	case mwapi.UDR:
		return gb.buildUDRGraph()
	}
	return nil
}

// Clear clears the content of the graph builder.
func (gb *GraphBuilder) Clear() {
	gb.globalConfig = nil
	gb.configsProvider = nil
	gb.graph.clear()
}

func (gb *GraphBuilder) getNodeConfigs(nodeType mwapi.LCNodeType) []config.NodeConfig {
	nodeConfigs := gb.configsProvider.GetDistributedNodeConfigs(nodeType)
	dutNodeConfig := gb.getDUTNodeConfig(nodeType)
	if dutNodeConfig != nil {
		nodeConfigs = append(nodeConfigs, *dutNodeConfig)
	}
	return nodeConfigs
}

func (gb *GraphBuilder) getPeerNodeConfigsMap(
	agentID string,
	nodeConnsSpec *nodeConnectionsSpec,
) map[mwapi.LCNodeType][]config.NodeConfig {
	peerMap := make(map[mwapi.LCNodeType][]config.NodeConfig)
	for _, connSpec := range nodeConnsSpec.connsSpec {
		nodeConfigs := gb.getPeerNodeConfigs(agentID, connSpec)
		if len(nodeConfigs) > 0 {
			peerMap[connSpec.peerNodeType] = nodeConfigs
		}
	}
	return peerMap
}

func (gb *GraphBuilder) getPeerNodeConfigs(agentID string, connSpec *connectionSpec) []config.NodeConfig {
	if connSpec.indirect {
		return gb.getNodeConfigs(connSpec.peerNodeType)
	}
	var nodeConfigs []config.NodeConfig
	nodeConfig := gb.configsProvider.GetDistributedPeerNodeConfig(
		agentID, connSpec.nodeType, connSpec.peerNodeType,
	)
	if nodeConfig != nil {
		nodeConfigs = append(nodeConfigs, *nodeConfig)
		return nodeConfigs
	}
	nodeConfig = gb.getDUTNodeConfig(connSpec.peerNodeType)
	if nodeConfig != nil {
		nodeConfigs = append(nodeConfigs, *nodeConfig)
	}
	return nodeConfigs
}

func (gb *GraphBuilder) getNodeFromGlobalConfig(nodeType mwapi.LCNodeType) *config.NodeConfig {
	configVal := reflect.ValueOf(gb.globalConfig)
	nodeFieldName := fmt.Sprintf("Nodes.%s", strings.Title(strings.ToLower(string(nodeType))))
	nodeVal := helpers.GetFieldByName(configVal, nodeFieldName)
	if !nodeVal.IsValid() {
		return nil
	}
	return &config.NodeConfig{
		AgentID: dutKey,
		Config:  nodeVal.Interface(),
	}
}

func (gb *GraphBuilder) getDUTNodeConfig(nodeType mwapi.LCNodeType) *config.NodeConfig {
	nodeConfig := gb.getNodeFromGlobalConfig(nodeType)
	if nodeConfig == nil {
		return nil
	}
	nodeRanges := helpers.GetEnabledNodeRanges(nodeConfig.Config)
	if !helpers.AllEnabledRangesAreDUT(nodeRanges) {
		return nil
	}
	return nodeConfig
}

func (gb *GraphBuilder) connectNodeToPeers(nodeConnsSpec *nodeConnectionsSpec, rangeProvider nodeRangeProvider) error {
	nodeConfigs := gb.getNodeConfigs(nodeConnsSpec.nodeType)
	for i := range nodeConfigs {
		nodeConfig := &nodeConfigs[i]
		if !helpers.NodeEnabled(nodeConfig.Config) {
			continue
		}
		nodeRanges := rangeProvider.getEnabledNodeRanges(nodeConfig.Config)
		if len(nodeRanges) == 0 {
			continue
		}
		var err error
		if helpers.AllEnabledRangesAreDUT(nodeRanges) {
			err = gb.connectDUTNodeToPeers(nodeConfig.AgentID, nodeRanges, nodeConnsSpec)
		} else {
			err = gb.connectDistribNodeToPeers(nodeConfig.AgentID, nodeRanges, nodeConnsSpec)
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
	nodeConnsSpec *nodeConnectionsSpec,
) error {
	peerMap := gb.getPeerNodeConfigsMap(nodeAgentID, nodeConnsSpec)
	if len(peerMap) == 0 {
		return nil
	}
	return gb.doConnectNodeToPeers(nodeAgentID, nodeRanges, peerMap, nodeConnsSpec)
}

func (gb *GraphBuilder) connectDUTNodeToPeers(
	nodeAgentID string,
	nodeRanges []interface{},
	nodeConnsSpec *nodeConnectionsSpec,
) error {
	peerMap := make(map[mwapi.LCNodeType][]config.NodeConfig)
	for _, peerNodeType := range nodeConnsSpec.peerNodeTypes {
		peerNodeConfigs := gb.getNodeConfigs(peerNodeType)
		peerMap[peerNodeType] = peerNodeConfigs
	}
	return gb.doConnectNodeToPeers(nodeAgentID, nodeRanges, peerMap, nodeConnsSpec)
}

func (gb *GraphBuilder) doConnectNodeToPeers(
	nodeAgentID string,
	nodeRanges []interface{},
	peerMap map[mwapi.LCNodeType][]config.NodeConfig,
	nodeConnsSpec *nodeConnectionsSpec,
) error {
	for i := range nodeRanges {
		for _, connSpec := range nodeConnsSpec.connsSpec {
			err := gb.doConnectNodeRangeToPeer(nodeAgentID, nodeRanges[i], peerMap, connSpec)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (gb *GraphBuilder) doConnectNodeRangeToPeer(
	nodeAgentID string,
	nodeRange interface{},
	peerMap map[mwapi.LCNodeType][]config.NodeConfig,
	connSpec *connectionSpec,
) error {
	for _, peerNode := range peerMap[connSpec.peerNodeType] {
		if !helpers.NodeEnabled(peerNode.Config) {
			continue
		}
		peerRanges := helpers.GetEnabledNodeRanges(peerNode.Config)
		for i := range peerRanges {
			err := gb.doConnectNodeRangeToPeerRange(
				nodeAgentID, nodeRange, peerNode.AgentID, peerRanges[i], connSpec,
			)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (gb *GraphBuilder) doConnectNodeRangeToPeerRange(
	nodeAgentID string,
	nodeRange interface{},
	peerAgentID string,
	peerRange interface{},
	connSpec *connectionSpec,
) error {
	if connSpec.indirect {
		return gb.graph.addConnectionForRanges(
			nodeAgentID, nodeRange, peerAgentID, peerRange, connSpec)
	}

	nodeRangeVal := reflect.ValueOf(nodeRange)
	remotePeerIDVal := helpers.TryGetFieldByName(nodeRangeVal, connSpec.fields.nodeRemotePeerID)
	if !remotePeerIDVal.IsValid() {
		return nil
	}
	peerRangeVal := reflect.ValueOf(peerRange)
	peerID := helpers.GetTypedFieldByName(peerRangeVal, "Id", reflect.String).String()

	switch remotePeerIDVal.Kind() {
	case reflect.String:
		if remotePeerIDVal.String() == peerID {
			return gb.graph.addConnectionForRanges(
				nodeAgentID, nodeRange, peerAgentID, peerRange, connSpec)
		}
	case reflect.Slice:
		for i := 0; i < remotePeerIDVal.Len(); i++ {
			kind := remotePeerIDVal.Index(i).Kind()
			if kind != reflect.String {
				panic(fmt.Errorf("wrong type for field %s[%d], expected string but got %s",
					connSpec.fields.nodeRemotePeerID, i, kind))
			}
			if remotePeerIDVal.Index(i).String() == peerID {
				err := gb.graph.addConnectionForRanges(
					nodeAgentID, nodeRange, peerAgentID, peerRange, connSpec,
				)
				if err != nil {
					return err
				}
			}
		}
	default:
		panic(fmt.Errorf("wrong type for field %s, expected string or slice of strings but got %s",
			connSpec.fields.nodeRemotePeerID, remotePeerIDVal.Kind()))
	}
	return nil
}
