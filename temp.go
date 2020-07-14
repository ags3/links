package connectivity

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"

	"bitbucket.it.keysight.com/isgappsec/mantisshrimp/go/cmd/wireless-data-model/data"
	"bitbucket.it.keysight.com/isgappsec/mantisshrimp/go/cmd/wireless-data-model/generated/mwapi"
	"bitbucket.it.keysight.com/isgappsec/mantisshrimp/go/cmd/wireless-data-model/generated/networkapi"
	"bitbucket.it.keysight.com/isgappsec/mantisshrimp/go/cmd/wireless-data-model/helpers"
	"bitbucket.it.keysight.com/isgappsec/mantisshrimp/go/lib/logging"
)

const (
	emptyGateway = "0.0.0.0"
)

// Uniquely identifies a node interface in the connectivity graph.
type nodeInterfaceID string

// Keeps node interface related data in the connectivity graph.
type nodeInterface struct {
	AgentID       string
	NodeType      mwapi.LCNodeType
	RangeID       string
	InterfaceType string
	IPAddr        string
	Gateway       *string
	IPPrefix      int32
	IsDUT         bool
}

// AgentNodeInterface keeps information about node interface types associated to an agent.
type AgentNodeInterface struct {
	AgentID       string
	NodeType      mwapi.LCNodeType
	InterfaceType string
}

// Graph is a directed graph keeping the connection information between node interfaces.
// Its is used for routing purposes: knowing the entire topology connectivity graph allows to
// build route structures which can be further used by callers to set up routes using the lizard
// REST API.
type Graph struct {
	logger                  *logging.Logger
	nodeInterfaces          map[nodeInterfaceID]*nodeInterface
	agentNodeInterfaces     map[AgentNodeInterface]map[nodeInterfaceID]struct{}
	connectedNodeInterfaces map[nodeInterfaceID]map[nodeInterfaceID]struct{}
}

func newNodeInterface(agentNodeIntf *AgentNodeInterface, nodeRange interface{}) (*nodeInterface, error) {
	nodeRangeVal := reflect.ValueOf(nodeRange)
	intfField := "Interfaces." + strings.Title(agentNodeIntf.InterfaceType)
	intfVal := helpers.FieldByName(nodeRangeVal, intfField)

	rangeID := helpers.FieldByName(nodeRangeVal, "Id").String()
	isDUT := helpers.FieldByName(nodeRangeVal, "IsDut").Bool()
	ipAddr := helpers.FieldByName(intfVal, "ConnectivitySettings.LocalIPAddress").String()
	ipPrefix := helpers.FieldByName(intfVal, "ConnectivitySettings.IpPrefix").Int()

	gatewayVal := helpers.FieldByName(intfVal, "ConnectivitySettings.GwStart")
	gateway, ok := gatewayVal.Interface().(*string)
	if !ok {
		return nil, errors.New("invalid value for GwStart field (not string)")
	}

	nodeIntf := &nodeInterface{
		AgentID:       agentNodeIntf.AgentID,
		NodeType:      agentNodeIntf.NodeType,
		RangeID:       rangeID,
		InterfaceType: strings.ToLower(agentNodeIntf.InterfaceType),
		IPAddr:        ipAddr,
		Gateway:       gateway,
		IPPrefix:      int32(ipPrefix),
		IsDUT:         isDUT,
	}

	return nodeIntf, nil
}

func (n *nodeInterface) id() nodeInterfaceID {
	id := []string{n.AgentID, string(n.NodeType), n.RangeID, n.InterfaceType}
	return nodeInterfaceID(strings.Join(id, "/"))
}

// String returns a textual representation of a node interface.
func (n *nodeInterface) String() string {
	gateway := emptyGateway
	if n.Gateway != nil {
		gateway = *n.Gateway
	}
	return fmt.Sprintf(
		"Agent=%s,Node=%s,Range=%s,Interface=%s,IP=%s,IPPrefix=%d,GW=%s,DUT=%t",
		n.AgentID, n.NodeType, n.RangeID, n.InterfaceType,
		n.IPAddr, n.IPPrefix, gateway, n.IsDUT)
}

func newGraph(logger *logging.Logger) *Graph {
	return &Graph{
		logger:                  logger,
		nodeInterfaces:          make(map[nodeInterfaceID]*nodeInterface),
		agentNodeInterfaces:     make(map[AgentNodeInterface]map[nodeInterfaceID]struct{}),
		connectedNodeInterfaces: make(map[nodeInterfaceID]map[nodeInterfaceID]struct{}),
	}
}

func (g *Graph) clear() {
	g.nodeInterfaces = make(map[nodeInterfaceID]*nodeInterface)
	g.agentNodeInterfaces = make(map[AgentNodeInterface]map[nodeInterfaceID]struct{})
	g.connectedNodeInterfaces = make(map[nodeInterfaceID]map[nodeInterfaceID]struct{})
}

func (g *Graph) addNodeInterface(id nodeInterfaceID, intf *nodeInterface) {
	if _, ok := g.nodeInterfaces[id]; !ok {
		g.nodeInterfaces[id] = intf
	}
	agentNodeIntf := AgentNodeInterface{
		AgentID:       intf.AgentID,
		NodeType:      intf.NodeType,
		InterfaceType: intf.InterfaceType,
	}
	if _, ok := g.agentNodeInterfaces[agentNodeIntf]; !ok {
		g.agentNodeInterfaces[agentNodeIntf] = make(map[nodeInterfaceID]struct{})
	}
	g.agentNodeInterfaces[agentNodeIntf][id] = struct{}{}
}

func (g *Graph) addDirectedConnection(srcID, destID nodeInterfaceID) {
	if _, ok := g.connectedNodeInterfaces[srcID]; !ok {
		g.connectedNodeInterfaces[srcID] = make(map[nodeInterfaceID]struct{})
	}
	g.connectedNodeInterfaces[srcID][destID] = struct{}{}
}

func (g *Graph) addConnection(srcIntf, destIntf *nodeInterface) error {
	srcID := srcIntf.id()
	destID := destIntf.id()

	needSrcDestRoute, err := g.needsRoute(srcIntf, destIntf)
	if err != nil {
		return err
	}

	needDestSrcRoute, err := g.needsRoute(destIntf, srcIntf)
	if err != nil {
		return err
	}

	if !needSrcDestRoute && !needDestSrcRoute {
		return nil
	}

	g.addNodeInterface(srcID, srcIntf)
	g.addNodeInterface(destID, destIntf)

	if needSrcDestRoute && !g.hasConnection(srcID, destID) {
		g.logger.Debug(fmt.Sprintf(
			"connectivity.Graph: connection: [%s] -> [%s]", srcIntf, destIntf))
		g.addDirectedConnection(srcID, destID)
	}

	if needDestSrcRoute && !g.hasConnection(destID, srcID) {
		g.logger.Debug(fmt.Sprintf(
			"connectivity.Graph: connection: [%s] -> [%s]", destIntf, srcIntf))
		g.addDirectedConnection(destID, srcID)
	}

	return nil
}

func (g *Graph) addConnectionForRanges(
	srcAgentNodeIntf *AgentNodeInterface,
	srcNodeRange interface{},
	destAgentNodeIntf *AgentNodeInterface,
	destNodeRange interface{},
) error {
	srcNodeIntf, err := newNodeInterface(srcAgentNodeIntf, srcNodeRange)
	if err != nil {
		return err
	}
	destNodeIntf, err := newNodeInterface(destAgentNodeIntf, destNodeRange)
	if err != nil {
		return err
	}
	return g.addConnection(srcNodeIntf, destNodeIntf)
}

func (g *Graph) hasConnection(srcIntfID, destIntfID nodeInterfaceID) bool {
	if _, ok := g.connectedNodeInterfaces[srcIntfID]; !ok {
		return false
	}
	_, ok := g.connectedNodeInterfaces[srcIntfID][destIntfID]
	return ok
}

func (g *Graph) numConnections() int {
	num := 0
	for id := range g.connectedNodeInterfaces {
		num += len(g.connectedNodeInterfaces[id])
	}
	return num
}

// Check if a route needs to be added between two node interfaces.
// In order for a route to be needed, the two node interfaces must satisfy the below conditions:
// - the source node should not be DUT.
// - the source and destination nodes should not have been distributed on the same agent.
// - the IP addresses of the source and destination node interfaces should not be in the
//   same subnet.
func (g *Graph) needsRoute(srcIntf, destIntf *nodeInterface) (bool, error) {
	if srcIntf.IsDUT || srcIntf.AgentID == destIntf.AgentID {
		return false, nil
	}
	sameSubnet, err := helpers.SameSubnet(
		srcIntf.IPAddr, srcIntf.IPPrefix, destIntf.IPAddr, destIntf.IPPrefix,
	)
	if err != nil {
		return false, err
	}
	return !sameSubnet, nil
}

// GetRoutes returns the routes for a node belonging to a given agent node interface.
func (g *Graph) GetRoutes(
	agentNodeIntf *AgentNodeInterface,
	agentDevice string,
	networkConfig data.NetworkConfig,
) ([]*networkapi.Route, error) {
	addrDevices, err := getAddrDeviceMap(networkConfig)
	if err != nil {
		return nil, err
	}

	var routes []*networkapi.Route

	intfIDs, ok := g.agentNodeInterfaces[*agentNodeIntf]
	if !ok {
		return routes, nil
	}

	// Traverse the edges of the connections graph and construct the necessary routes.
	for intfID := range intfIDs {
		peerIntfIDs, ok := g.connectedNodeInterfaces[intfID]
		if !ok {
			continue
		}

		intf := g.nodeInterfaces[intfID]

		for peerIntfID := range peerIntfIDs {
			peerIntf := g.nodeInterfaces[peerIntfID]

			// Try to identify the device to which the source node address is bound to in order to
			// use it as route output device.
			// If we fail to do this, fallback to the agent device.
			device, ok := addrDevices[intf.IPAddr]
			if !ok {
				device = agentDevice
			}

			route, err := g.getRoute(intf, peerIntf, device)
			if err != nil {
				return nil, err
			}

			routes = append(routes, route)
		}
	}
	g.logger.Debug(fmt.Sprintf("connectivity.Graph: constructed %d routes", len(routes)))
	return routes, nil
}

func (g *Graph) getRoute(srcIntf, destIntf *nodeInterface, device string) (*networkapi.Route, error) {
	fullDestIP := fmt.Sprintf("%s/%d", destIntf.IPAddr, destIntf.IPPrefix)
	_, destNetAddr, err := net.ParseCIDR(fullDestIP)

	if err != nil {
		return nil, err
	}

	destIPNetPrefix, _ := destNetAddr.Mask.Size()
	defaultScope := networkapi.UNIVERSE

	route := &networkapi.Route{
		Dev:       device,
		Dst:       destNetAddr.IP.String(),
		DstPrefix: int32(destIPNetPrefix),
		Gateway:   srcIntf.Gateway,
		Scope:     &defaultScope,
	}

	return route, nil
}

// Parse the network configuration and return a map from IP addresses to their associated device.
// The network configuration has the following format:
// map[intf/device][type: data.VLAN, data.IP, data.ROUTE, data.DPDK][][]byte
func getAddrDeviceMap(networkConfig data.NetworkConfig) (map[string]string, error) {
	addrDevices := make(map[string]string)
	for device, configTypeMap := range networkConfig {
		for configType, configBlobs := range configTypeMap {
			if configType != data.IP {
				continue
			}
			for _, configBlob := range configBlobs {
				var addr networkapi.Address

				err := json.Unmarshal(configBlob, &addr)
				if err != nil {
					return nil, err
				}
				addrDevices[addr.Addr] = device
			}
		}
	}
	return addrDevices, nil
}
