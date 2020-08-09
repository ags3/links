package connectivity

import (
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"strings"

	"bitbucket.it.keysight.com/isgappsec/mantisshrimp/go/cmd/wireless-data-model/data"
	"bitbucket.it.keysight.com/isgappsec/mantisshrimp/go/cmd/wireless-data-model/generated/mwapi"
	netapi "bitbucket.it.keysight.com/isgappsec/mantisshrimp/go/cmd/wireless-data-model/generated/networkapi"
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
	agentID       string
	nodeType      mwapi.LCNodeType
	rangeID       string
	interfaceType string
	ipAddr        string
	gateway       *string
	ipPrefix      int32
	isDUT         bool
}

// AgentNodeInterface keeps information about node interface types associated to an agent.
type AgentNodeInterface struct {
	AgentID       string
	NodeType      mwapi.LCNodeType
	InterfaceType string
}

// Used to mark the processed routes.
type routeKey struct {
	agentID   string
	dev       string
	dst       string
	dstPrefix int32
	gateway   string
}

// Graph is a directed graph keeping the connection information between node interfaces.
// Its is currently used for routing purposes: knowing the entire topology connectivity graph
// allows to build route structures which can be further used by callers to set up routes using the
// lizard REST API.
type Graph struct {
	logger                  *logging.Logger
	nodeInterfaces          map[nodeInterfaceID]*nodeInterface
	agentNodeInterfaces     map[AgentNodeInterface][]nodeInterfaceID
	connectedNodeInterfaces map[nodeInterfaceID]map[nodeInterfaceID]struct{}
	processedRoutes         map[routeKey]struct{}
}

func newNodeInterface(agentID string, nodeRange interface{}, connSpec *connectionSpec, isSource bool) *nodeInterface {
	var (
		nodeType      mwapi.LCNodeType
		intfType      string
		ipAddrField   string
		ipPrefixField string
		gatewayField  string
	)

	if isSource {
		nodeType = connSpec.nodeType
		intfType = connSpec.nodeIntf
		ipAddrField = connSpec.fields.nodeIPAddress
		ipPrefixField = connSpec.fields.nodeIPPrefix
		gatewayField = connSpec.fields.nodeGateway
	} else {
		nodeType = connSpec.peerNodeType
		intfType = connSpec.peerNodeIntf
		ipAddrField = connSpec.fields.peerIPAddress
		ipPrefixField = connSpec.fields.peerIPPrefix
		gatewayField = connSpec.fields.peerGateway
	}

	nodeRangeVal := reflect.ValueOf(nodeRange)
	rangeIDVal := helpers.TryGetFieldByName(nodeRangeVal, "Id")
	if !rangeIDVal.IsValid() {
		return nil
	}
	rangeID := rangeIDVal.String()

	var isDUT bool
	isDUTVal := helpers.TryGetFieldByName(nodeRangeVal, "IsDut")
	if isDUTVal.IsValid() {
		isDUT = isDUTVal.Bool()
	}

	ipAddrVal := helpers.TryGetFieldByName(nodeRangeVal, ipAddrField)
	if !ipAddrVal.IsValid() {
		return nil
	}
	ipAddr, ok := ipAddrVal.Interface().(string)
	if !ok {
		return nil
	}

	ipPrefixVal := helpers.TryGetFieldByName(nodeRangeVal, ipPrefixField)
	if !ipPrefixVal.IsValid() {
		return nil
	}
	ipPrefix, ok := ipPrefixVal.Interface().(int32)
	if !ok {
		return nil
	}

	var gateway *string
	gatewayVal := helpers.TryGetFieldByName(nodeRangeVal, gatewayField)
	if gatewayVal.IsValid() {
		var ok bool
		gateway, ok = gatewayVal.Interface().(*string)
		if !ok {
			return nil
		}
	}

	return &nodeInterface{
		agentID:       agentID,
		nodeType:      nodeType,
		rangeID:       rangeID,
		interfaceType: intfType,
		ipAddr:        ipAddr,
		gateway:       gateway,
		ipPrefix:      ipPrefix,
		isDUT:         isDUT,
	}
}

func (n *nodeInterface) id() nodeInterfaceID {
	id := []string{n.agentID, string(n.nodeType), n.rangeID, n.interfaceType}
	return nodeInterfaceID(strings.Join(id, "/"))
}

// String returns a textual representation of a node interface.
func (n *nodeInterface) String() string {
	gateway := emptyGateway
	if n.gateway != nil {
		gateway = *n.gateway
	}
	return fmt.Sprintf(
		"Agent=%s,Node=%s,Range=%s,Interface=%s,IP=%s,IPPrefix=%d,GW=%s,DUT=%t",
		n.agentID, n.nodeType, n.rangeID, n.interfaceType,
		n.ipAddr, n.ipPrefix, gateway, n.isDUT)
}

func newGraph(logger *logging.Logger) *Graph {
	return &Graph{
		logger:                  logger,
		nodeInterfaces:          make(map[nodeInterfaceID]*nodeInterface),
		agentNodeInterfaces:     make(map[AgentNodeInterface][]nodeInterfaceID),
		connectedNodeInterfaces: make(map[nodeInterfaceID]map[nodeInterfaceID]struct{}),
		processedRoutes:         make(map[routeKey]struct{}),
	}
}

func (g *Graph) clear() {
	g.nodeInterfaces = make(map[nodeInterfaceID]*nodeInterface)
	g.agentNodeInterfaces = make(map[AgentNodeInterface][]nodeInterfaceID)
	g.connectedNodeInterfaces = make(map[nodeInterfaceID]map[nodeInterfaceID]struct{})
	g.processedRoutes = make(map[routeKey]struct{})
}

func (g *Graph) addNodeInterface(id nodeInterfaceID, intf *nodeInterface) {
	if _, ok := g.nodeInterfaces[id]; ok {
		return
	}
	g.nodeInterfaces[id] = intf
	agentNodeIntf := AgentNodeInterface{
		AgentID:       intf.agentID,
		NodeType:      intf.nodeType,
		InterfaceType: intf.interfaceType,
	}
	g.agentNodeInterfaces[agentNodeIntf] = append(g.agentNodeInterfaces[agentNodeIntf], id)
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
		g.logger.Debug(fmt.Sprintf(
			"connectivity: skipping connection: [%s] <-> [%s]", srcIntf, destIntf))
		return nil
	}

	g.addNodeInterface(srcID, srcIntf)
	g.addNodeInterface(destID, destIntf)

	if needSrcDestRoute && !g.hasConnection(srcID, destID) {
		g.logger.Debug(fmt.Sprintf(
			"connectivity: adding connection: [%s] -> [%s]", srcIntf, destIntf))
		g.addDirectedConnection(srcID, destID)
	} else {
		g.logger.Debug(fmt.Sprintf(
			"connectivity: skipping connection: [%s] -> [%s]", srcIntf, destIntf))
	}
	if needDestSrcRoute && !g.hasConnection(destID, srcID) {
		g.logger.Debug(fmt.Sprintf(
			"connectivity: adding connection: [%s] -> [%s]", destIntf, srcIntf))
		g.addDirectedConnection(destID, srcID)
	} else {
		g.logger.Debug(fmt.Sprintf(
			"connectivity: skipping connection: [%s] -> [%s]", destIntf, srcIntf))
	}
	return nil
}

func (g *Graph) addConnectionForRanges(srcRange, destRange *agentRange, connSpec *connectionSpec) error {
	srcNodeIntf := newNodeInterface(srcRange.agentID, srcRange.nodeRange, connSpec, true)
	if srcNodeIntf == nil {
		return nil
	}
	destNodeIntf := newNodeInterface(destRange.agentID, destRange.nodeRange, connSpec, false)
	if destNodeIntf == nil {
		return nil
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
// - the source node should have a gateway set.
// - the source and destination nodes should not have been distributed on the same agent.
// - the IP addresses of the source and destination node interfaces should not be in the
//   same subnet.
func (g *Graph) needsRoute(srcIntf, destIntf *nodeInterface) (bool, error) {
	if srcIntf.isDUT || srcIntf.gateway == nil || srcIntf.agentID == destIntf.agentID {
		return false, nil
	}
	sameSubnet, err := helpers.SameSubnet(
		srcIntf.ipAddr, srcIntf.ipPrefix, destIntf.ipAddr, destIntf.ipPrefix,
	)
	if err != nil {
		return false, err
	}
	return !sameSubnet, nil
}

// GetRoutes returns the routes for a node belonging to a given agent node interface.
func (g *Graph) GetRoutes(agentIntf *AgentNodeInterface, agentDev string, cfg data.NetworkConfig) ([]*netapi.Route, error) {
	intfIDs, ok := g.agentNodeInterfaces[*agentIntf]
	if !ok {
		return nil, nil
	}
	addrDevMap, err := getAddrDeviceMap(cfg)
	if err != nil {
		return nil, err
	}
	var routes []*netapi.Route

	// Traverse the edges of the connections graph and construct the necessary routes.
	for _, intfID := range intfIDs {
		peerIntfIDs, ok := g.connectedNodeInterfaces[intfID]
		if !ok {
			continue
		}

		intf := g.nodeInterfaces[intfID]

		for peerIntfID := range peerIntfIDs {
			// Try to identify the device to which the interface address is bound,
			// using the IP address to device map.
			// If we fail to do this, fallback to the agent device.
			dev, ok := addrDevMap[intf.ipAddr]
			if !ok {
				dev = agentDev
			}
			// Add a new route only if we haven't processed it before.
			peerIntf := g.nodeInterfaces[peerIntfID]
			route, err := g.getRoute(intf, peerIntf, dev)
			if err != nil {
				return nil, err
			}
			routeKey := g.getRouteKey(agentIntf.AgentID, route)
			if _, ok := g.processedRoutes[*routeKey]; ok {
				continue
			}
			g.processedRoutes[*routeKey] = struct{}{}
			routes = append(routes, route)
		}
	}
	g.logger.Info(fmt.Sprintf("connectivity.Graph: constructed %d routes", len(routes)))
	return routes, nil
}

func (g *Graph) getRoute(srcIntf, destIntf *nodeInterface, dev string) (*netapi.Route, error) {
	fullDestIP := fmt.Sprintf("%s/%d", destIntf.ipAddr, destIntf.ipPrefix)
	_, destNetAddr, err := net.ParseCIDR(fullDestIP)
	if err != nil {
		return nil, err
	}

	gateway := emptyGateway
	if srcIntf.gateway != nil {
		gateway, err = helpers.NormalizeIPAddress(*srcIntf.gateway)
		if err != nil {
			return nil, err
		}
	}

	destIPNetPrefix, _ := destNetAddr.Mask.Size()
	defaultScope := netapi.UNIVERSE

	route := &netapi.Route{
		Dev:       dev,
		Dst:       destNetAddr.IP.String(),
		DstPrefix: int32(destIPNetPrefix),
		Gateway:   &gateway,
		Scope:     &defaultScope,
	}

	return route, nil
}

func (g *Graph) getRouteKey(agentID string, route *netapi.Route) *routeKey {
	gateway := emptyGateway
	if route.Gateway != nil {
		gateway = *route.Gateway
	}
	return &routeKey{
		agentID:   agentID,
		dev:       route.Dev,
		dst:       route.Dst,
		dstPrefix: route.DstPrefix,
		gateway:   gateway,
	}
}

// Parse the network configuration and return a map from IP addresses to their associated device.
// The network configuration has the following format:
// map[intf/device][type: data.VLAN, data.IP, data.ROUTE, data.DPDK][][]byte
func getAddrDeviceMap(cfg data.NetworkConfig) (map[string]string, error) {
	addrDevMap := make(map[string]string)
	for dev, cfgTypeMap := range cfg {
		for cfgType, cfgBlobs := range cfgTypeMap {
			if cfgType != data.IP {
				continue
			}
			for _, cfgBlob := range cfgBlobs {
				var addr netapi.Address

				err := json.Unmarshal(cfgBlob, &addr)
				if err != nil {
					return nil, err
				}
				addrDevMap[addr.Addr] = dev
			}
		}
	}
	return addrDevMap, nil
}
