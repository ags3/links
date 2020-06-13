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
	"bitbucket.it.keysight.com/isgappsec/mantisshrimp/go/lib/logging"
)

// NodeInterfaceID uniquely identifies a node interface in the connectivity
// graph.
type NodeInterfaceID string

// NodeInterface keeps node interface related data in the connectivity graph.
type NodeInterface struct {
	AgentID       string
	NodeType      mwapi.LCNodeType
	RangeID       string
	InterfaceType string
	IPAddr        string
	Gateway       *string
	IPPrefix      int32
	IsDUT         bool
}

// AgentNodeInterface keeps information about node interface types associated
// to an agent.
type AgentNodeInterface struct {
	AgentID       string
	NodeType      mwapi.LCNodeType
	InterfaceType string
}

// RemoteNetworkDevice keeps data about a route destination network address
// and prefix and the output interface device.
type RemoteNetworkDevice struct {
	Device           string
	DstNetworkAddr   string
	DstNetworkPrefix int32
}

// Graph is an undirected graph keeping the connection information between
// node interfaces.
// Its main usage is for routing purposes: knowing the entire topology
// connectivity graph allows to build route structures which can be further
// used by callers to set up routes using the lizard REST API.
type Graph struct {
	logger                  *logging.Logger
	nodeInterfaces          map[NodeInterfaceID]*NodeInterface
	AgentNodeInterfaces     map[AgentNodeInterface]map[NodeInterfaceID]struct{}
	connectedNodeInterfaces map[NodeInterfaceID]map[NodeInterfaceID]struct{}
}

// NewNodeInterface creates a new node interface for the connectivity graph.
func NewNodeInterface(
	agentID string,
	nodeType mwapi.LCNodeType,
	rangeID string,
	intfType string,
	ipAddr string,
	gateway *string,
	ipPrefix int32,
	isDUT bool,
) *NodeInterface {
	return &NodeInterface{
		AgentID:       agentID,
		NodeType:      nodeType,
		RangeID:       rangeID,
		InterfaceType: strings.ToLower(intfType),
		IPAddr:        ipAddr,
		Gateway:       gateway,
		IPPrefix:      ipPrefix,
		IsDUT:         isDUT,
	}
}

// NewNodeInterfaceForRange creates a node interface using data from a
// generic node range.
func NewNodeInterfaceForRange(
	agentID string,
	nodeType mwapi.LCNodeType,
	intfType string,
	nodeRange interface{},
) (*NodeInterface, error) {
	nodeRangeValue := reflect.ValueOf(nodeRange)
	if nodeRangeValue.Kind() == reflect.Ptr {
		if nodeRangeValue.IsNil() {
			return nil, errors.New("invalid value for node range")
		}
		nodeRangeValue = reflect.Indirect(nodeRangeValue)
	}

	intfValue := nodeRangeValue.FieldByName("Interfaces").
		FieldByName(strings.Title(intfType))

	if intfValue.Kind() == reflect.Ptr {
		if intfValue.IsNil() {
			return nil, errors.New("invalid value for Interfaces field")
		}
		intfValue = reflect.Indirect(intfValue)
	}

	rangeID := nodeRangeValue.FieldByName("Id").String()
	isDUT := nodeRangeValue.FieldByName("IsDut").Bool()

	ipAddr := intfValue.FieldByName("ConnectivitySettings").
		FieldByName("LocalIPAddress").String()
	ipPrefix := intfValue.FieldByName("ConnectivitySettings").
		FieldByName("IpPrefix").Int()

	gateway, ok := intfValue.FieldByName("ConnectivitySettings").
		FieldByName("GwStart").Interface().(*string)
	if !ok {
		return nil, errors.New("invalid value for GwStart field (not string)")
	}

	nodeIntf := NewNodeInterface(
		agentID,
		nodeType,
		rangeID,
		intfType,
		ipAddr,
		gateway,
		int32(ipPrefix),
		isDUT,
	)

	return nodeIntf, nil
}

// ID returns a string which uniquely identifies a node interface in the
// connectivity graph.
func (n *NodeInterface) ID() NodeInterfaceID {
	id := []string{n.AgentID, string(n.NodeType), n.RangeID, n.InterfaceType}
	return NodeInterfaceID(strings.Join(id, "/"))
}

// String returns a textual representation of a node interface.
func (n *NodeInterface) String() string {
	gateway := "none"
	if n.Gateway != nil {
		gateway = *n.Gateway
	}
	return fmt.Sprintf(
		"Agent=%s,Node=%s,Range=%s,Interface=%s,IP=%s,IPPrefix=%d,GW=%s,DUT=%t",
		n.AgentID, n.NodeType, n.RangeID, n.InterfaceType,
		n.IPAddr, n.IPPrefix, gateway, n.IsDUT)
}

// NewGraph is used to create a new connectivity graph.
func NewGraph(logger *logging.Logger) *Graph {
	return &Graph{
		logger:                  logger,
		nodeInterfaces:          make(map[NodeInterfaceID]*NodeInterface),
		AgentNodeInterfaces:     make(map[AgentNodeInterface]map[NodeInterfaceID]struct{}),
		connectedNodeInterfaces: make(map[NodeInterfaceID]map[NodeInterfaceID]struct{}),
	}
}

func (g *Graph) addNodeInterface(id NodeInterfaceID, intf *NodeInterface) {
	if _, ok := g.nodeInterfaces[id]; !ok {
		g.nodeInterfaces[id] = intf
	}
	agentNodeIntf := AgentNodeInterface{
		AgentID:       intf.AgentID,
		NodeType:      intf.NodeType,
		InterfaceType: intf.InterfaceType,
	}
	if _, ok := g.AgentNodeInterfaces[agentNodeIntf]; !ok {
		g.AgentNodeInterfaces[agentNodeIntf] = make(map[NodeInterfaceID]struct{})
	}
	g.AgentNodeInterfaces[agentNodeIntf][id] = struct{}{}
}

func (g *Graph) addDirectedConnection(srcID, destID NodeInterfaceID) {
	if _, ok := g.connectedNodeInterfaces[srcID]; !ok {
		g.connectedNodeInterfaces[srcID] = make(map[NodeInterfaceID]struct{})
	}
	g.connectedNodeInterfaces[srcID][destID] = struct{}{}
}

// AddConnection is used to add a new connection between two node interfaces.
func (g *Graph) AddConnection(srcIntf, destIntf *NodeInterface) {
	srcID := srcIntf.ID()
	destID := destIntf.ID()
	if g.HasConnection(srcID, destID) {
		return
	}
	g.logger.Debug(fmt.Sprintf(
		"connectivity.Graph: new connection: [%s] <-> [%s]", srcIntf, destIntf))
	g.addNodeInterface(srcID, srcIntf)
	g.addNodeInterface(destID, destIntf)
	g.addDirectedConnection(srcID, destID)
	g.addDirectedConnection(destID, srcID)
}

// AddConnectionForRanges is used to add a new connection between two node
// interfaces populated with data from two generic node ranges.
func (g *Graph) AddConnectionForRanges(
	srcAgentID string,
	srcNodeType mwapi.LCNodeType,
	srcIntfType string,
	srcNodeRange interface{},
	destAgentID string,
	destNodeType mwapi.LCNodeType,
	destIntfType string,
	destNodeRange interface{},
) error {
	srcNodeIntf, err := NewNodeInterfaceForRange(
		srcAgentID, srcNodeType, srcIntfType, srcNodeRange)

	if err != nil {
		g.logger.Error(fmt.Sprintf(
			"connectivity.Graph: error parsing range data for %s/%s/%s: %s",
			srcAgentID, srcNodeType, srcIntfType, err))
		return err
	}

	destNodeIntf, err := NewNodeInterfaceForRange(
		destAgentID, destNodeType, destIntfType, destNodeRange)

	if err != nil {
		g.logger.Error(fmt.Sprintf(
			"connectivity.Graph: error parsing range data for %s/%s/%s: %s",
			destAgentID, destNodeType, destIntfType, err))
		return err
	}

	g.AddConnection(srcNodeIntf, destNodeIntf)
	return nil
}

// HasConnection is used to check if two node interfaces are connected.
func (g *Graph) HasConnection(srcIntfID, destIntfID NodeInterfaceID) bool {
	if _, ok := g.connectedNodeInterfaces[srcIntfID]; !ok {
		return false
	}
	_, ok := g.connectedNodeInterfaces[srcIntfID][destIntfID]
	return ok
}

// NumConnections is used to get the number of connections in the connectivity
// graph.
func (g *Graph) NumConnections() int {
	num := 0
	for id := range g.connectedNodeInterfaces {
		num += len(g.connectedNodeInterfaces[id])
	}
	return num
}

// NeedsRoute checks if a route needs to be added between two node interfaces.
// In order for a route to be needed, the two node interfaces must satisfy
// the below conditions:
// - the source node should not be DUT.
// - the source node should have a gateway set by user
//   (not nil and not equal to the default value "0.0.0.0" set by GUI).
// - the source and destination nodes should not have been distributed on the
//   same agent.
// - the IP addresses of the source and destination node interfaces should not
//   be in the same subnet.
func (g *Graph) NeedsRoute(srcIntf, destIntf *NodeInterface) (bool, error) {
	if srcIntf.IsDUT || srcIntf.Gateway == nil ||
		*srcIntf.Gateway == "0.0.0.0" ||
		srcIntf.AgentID == destIntf.AgentID {
		return false, nil
	}

	sameSubnet, err := addressesInSameSubnet(srcIntf.IPAddr, srcIntf.IPPrefix,
		destIntf.IPAddr, destIntf.IPPrefix)

	if err != nil {
		g.logger.Error(fmt.Sprintf(
			"connectivity.Graph: error parsing IP addresses %s/%d or %s/%d: %s",
			srcIntf.IPAddr, srcIntf.IPPrefix,
			destIntf.IPAddr, destIntf.IPPrefix, err))
		return false, err
	}
	return !sameSubnet, nil
}

// GetRoutes returns the routes for a node belonging to a given agent node
// interface.
// The 'addedRoutesInfo' parameter is used to keep track of what routes were
// already added to a remote network address on each device (in order to
// prevent trying to add multiple routes to the same network address and on
// the same device).
func (g *Graph) GetRoutes(
	agentNodeIntf *AgentNodeInterface,
	agentDevice string,
	networkConfig data.NetworkConfig,
	addedRoutesInfo map[RemoteNetworkDevice]string,
) ([]*networkapi.Route, error) {
	addrDevices, err := parseAddrDeviceMap(networkConfig)
	if err != nil {
		return nil, err
	}

	var routes []*networkapi.Route

	intfIDs, ok := g.AgentNodeInterfaces[*agentNodeIntf]
	if !ok {
		return routes, nil
	}

	for intfID := range intfIDs {
		peerIntfIDs, ok := g.connectedNodeInterfaces[intfID]
		if !ok {
			continue
		}

		intf := g.nodeInterfaces[intfID]

		for peerIntfID := range peerIntfIDs {
			peerIntf := g.nodeInterfaces[peerIntfID]
			needsRoute, err := g.NeedsRoute(intf, peerIntf)
			if err != nil {
				return nil, err
			}
			if !needsRoute {
				continue
			}

			// Try to identify the device to which the source node address is
			// bound to in order to use it as route device.
			// If we fail to do this, fallback to the agent device.
			device, ok := addrDevices[intf.IPAddr]
			if !ok {
				device = agentDevice
			}

			route, err := g.getRoute(intf, peerIntf, device)
			if err != nil {
				return nil, err
			}

			remoteNetDevice := RemoteNetworkDevice{
				Device:           route.Dev,
				DstNetworkAddr:   route.Dst,
				DstNetworkPrefix: route.DstPrefix,
			}

			var routeGateway string
			if route.Gateway != nil {
				routeGateway = *route.Gateway
			}

			if gateway, ok := addedRoutesInfo[remoteNetDevice]; ok {
				if gateway != routeGateway {
					g.logger.Warning(fmt.Sprintf(
						"connectivity.Graph: A route to network %s/%d using "+
							"device %s was already added (via gateway %s). "+
							"Ignoring setting a new route via gateway %s",
						remoteNetDevice.DstNetworkAddr,
						remoteNetDevice.DstNetworkPrefix,
						remoteNetDevice.Device,
						gateway,
						routeGateway))
				}
				continue
			}

			addedRoutesInfo[remoteNetDevice] = routeGateway
			routes = append(routes, route)
		}
	}

	g.logger.Debug(fmt.Sprintf("connectivity.Graph: constructed %d routes",
		len(routes)))

	return routes, nil
}

func (g *Graph) getRoute(srcIntf, destIntf *NodeInterface, device string) (*networkapi.Route, error) {
	_, destNetAddr, err := parseIPAddress(destIntf.IPAddr, destIntf.IPPrefix)
	if err != nil {
		g.logger.Error(fmt.Sprintf(
			"connectivity.Graph: error parsing IP address %s/%d: %s",
			destIntf.IPAddr, destIntf.IPPrefix, err))
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

func parseIPAddress(ip string, ipPrefix int32) (net.IP, *net.IPNet, error) {
	fullIP := fmt.Sprintf("%s/%d", ip, ipPrefix)
	ipAddr, netAddr, err := net.ParseCIDR(fullIP)
	if err != nil {
		return nil, nil, err
	}
	return ipAddr, netAddr, nil
}

func addressesInSameSubnet(
	srcIP string,
	srcIPPrefix int32,
	destIP string,
	destIPPrefix int32,
) (bool, error) {
	_, srcNetAddr, err := parseIPAddress(srcIP, srcIPPrefix)
	if err != nil {
		return false, err
	}
	destIPAddr, _, err := parseIPAddress(destIP, destIPPrefix)
	if err != nil {
		return false, err
	}
	if !srcNetAddr.Contains(destIPAddr) {
		return false, nil
	}
	return true, nil
}

// Parse the network configuration and return a map from IP addresses to their
// associated device.
func parseAddrDeviceMap(networkConfig data.NetworkConfig) (map[string]string, error) {
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
