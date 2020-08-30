package connectivity

import (
	"reflect"

	"bitbucket.it.keysight.com/isgappsec/mantisshrimp/go/cmd/wireless-data-model/generated/mwapi"
	"bitbucket.it.keysight.com/isgappsec/mantisshrimp/go/cmd/wireless-data-model/helpers"
	"bitbucket.it.keysight.com/isgappsec/mantisshrimp/go/cmd/wireless-data-model/nodes/config"
	"bitbucket.it.keysight.com/isgappsec/mantisshrimp/go/cmd/wireless-data-model/rest/model"
)

// Keeps the association for the matching ranges between UE and the node acting as gateway between
// the DN and UEs (e.g UPF).
// Also keeps the agent ID of the RAN on which the UE ranges were distributed.
type ueDNGatewayRangesInfo struct {
	ranAgentID      string
	ueRanges        []interface{}
	dnGatewayRanges []interface{}
}

// Keeps the routing information between DN and UE ranges (extracted from a DN range).
type dnUERouteInfo struct {
	dnAgentID        string
	ueRangeID        string
	dnGatewayRangeID string
	dnRange          interface{}
}

func (gb *GraphBuilder) buildDNGraph() error {
	if gb.topology != model.FullCore && gb.topology != model.UPFIsolation {
		return nil
	}
	routesInfo := gb.getDNToUERoutesInfo()
	if len(routesInfo) == 0 {
		return nil
	}
	peerRanges := gb.getUEAndDNGatewayRanges()
	for i := range routesInfo {
		for j := range peerRanges {
			gb.doBuildDNGraph(routesInfo[i], peerRanges[j])
		}
	}
	return nil
}

func (gb *GraphBuilder) doBuildDNGraph(routeInfo *dnUERouteInfo, rangesInfo *ueDNGatewayRangesInfo) {
	var ueRange, dnGatewayRange interface{}

	for i := range rangesInfo.ueRanges {
		rangeVal := reflect.ValueOf(rangesInfo.ueRanges[i])
		rangeIDVal := helpers.GetTypedFieldByName(rangeVal, "Id", reflect.String)
		rangeID := rangeIDVal.String()
		if rangeID == routeInfo.ueRangeID {
			ueRange = rangesInfo.ueRanges[i]
			break
		}
	}
	for i := range rangesInfo.dnGatewayRanges {
		rangeVal := reflect.ValueOf(rangesInfo.dnGatewayRanges[i])
		rangeIDVal := helpers.GetTypedFieldByName(rangeVal, "Id", reflect.String)
		rangeID := rangeIDVal.String()
		if rangeID == routeInfo.dnGatewayRangeID {
			dnGatewayRange = rangesInfo.dnGatewayRanges[i]
			break
		}
	}

	if ueRange != nil && dnGatewayRange != nil {
		gb.connectRanges(routeInfo, rangesInfo.ranAgentID, ueRange, dnGatewayRange)
	}
}

func (gb *GraphBuilder) connectRanges(routeInfo *dnUERouteInfo, ranAgentID string, ueRange, dnGatewayRange interface{}) {
	dnNodeIntf := gb.newDNNodeInterface(routeInfo, dnGatewayRange)
	if dnNodeIntf == nil {
		return
	}
	ueIPs := gb.getUERangeIPs(ueRange)
	for _, ueIP := range ueIPs {
		ueNodeIntf := gb.newUENodeInterface(routeInfo, ranAgentID, ueRange, ueIP)
		if ueNodeIntf == nil {
			continue
		}
		err := gb.graph.addConnection(dnNodeIntf, ueNodeIntf, true)
		if err != nil {
			gb.logger.Warning("Cannot add graph connection from DN to UE")
		}
	}
}

func (gb *GraphBuilder) newUENodeInterface(
	routeInfo *dnUERouteInfo,
	ranAgentID string,
	ueRange interface{},
	ueIP string,
) *nodeInterface {
	ipPrefix := getRangeIPPrefix(ueRange, "", ueIP)
	if ipPrefix == -1 {
		gb.logger.Warning("Cannot get the IP prefix of UE range")
		return nil
	}

	ueRangeVal := reflect.ValueOf(ueRange)
	isDUTVal := helpers.TryGetFieldByName(ueRangeVal, "IsDut")
	isDUT := isDUTVal.IsValid() && isDUTVal.Bool()

	return &nodeInterface{
		agentID:       ranAgentID,
		nodeType:      mwapi.UE,
		rangeID:       routeInfo.ueRangeID,
		interfaceType: "n3",
		ipAddr:        ueIP,
		ipPrefix:      ipPrefix,
		isDUT:         isDUT,
	}
}

func (gb *GraphBuilder) newDNNodeInterface(routeInfo *dnUERouteInfo, dnGatewayRange interface{}) *nodeInterface {
	dnRangeVal := reflect.ValueOf(routeInfo.dnRange)
	dnRangeIDVal := helpers.GetTypedFieldByName(dnRangeVal, "Id", reflect.String)
	dnRangeID := dnRangeIDVal.String()

	ipAddrVal := helpers.GetTypedFieldByName(
		dnRangeVal, "Interfaces.N6.ConnectivitySettings.LocalIPAddress", reflect.String,
	)
	ipAddr := ipAddrVal.String()

	ipPrefix := getRangeIPPrefix(
		routeInfo.dnRange, "Interfaces.N6.ConnectivitySettings.IpPrefix", ipAddr,
	)
	if ipPrefix == -1 {
		gb.logger.Warning("Cannot get the IP prefix of DN range")
		return nil
	}

	dnGatewayRangeVal := reflect.ValueOf(dnGatewayRange)
	gatewayVal := helpers.GetTypedFieldByName(
		dnGatewayRangeVal,
		"Interfaces.N6.ConnectivitySettings.LocalIPAddress",
		reflect.String,
	)
	gateway := gatewayVal.String()

	return &nodeInterface{
		agentID:       routeInfo.dnAgentID,
		nodeType:      mwapi.DN,
		rangeID:       dnRangeID,
		interfaceType: "n6",
		ipAddr:        ipAddr,
		gateway:       &gateway,
		ipPrefix:      ipPrefix,
		isDUT:         false,
	}
}

func (gb *GraphBuilder) getDNToUERoutesInfo() []*dnUERouteInfo {
	dns := gb.getNodeConfigs(mwapi.DN)
	routesInfo := make([]*dnUERouteInfo, 0, len(dns))

	rangeProvider := getNodeRangeProvider(mwapi.DN)

	for i := range dns {
		dn := &dns[i]
		dnRanges := rangeProvider.getEnabledNodeRanges(dn.Config)
		for j := range dnRanges {
			dnRangeVal := reflect.ValueOf(dnRanges[j])
			isDUTVal := helpers.TryGetFieldByName(dnRangeVal, "IsDut")
			if isDUTVal.IsValid() && isDUTVal.Bool() {
				continue
			}
			ueRoutesVal := helpers.GetTypedFieldByName(
				dnRangeVal, "UeRoutes", reflect.Slice,
			)
			for k := 0; k < ueRoutesVal.Len(); k++ {
				dnUERoute, ok := ueRoutesVal.Index(i).Interface().(mwapi.DnUeRoute)
				if !ok {
					panic("Invalid type for DN UE route")
				}
				routeInfo := dnUERouteInfo{
					dnAgentID:        dn.AgentID,
					ueRangeID:        dnUERoute.UeRangeId,
					dnGatewayRangeID: dnUERoute.GatewayRangeId,
					dnRange:          dnRanges[j],
				}
				routesInfo = append(routesInfo, &routeInfo)
			}
		}
	}
	return routesInfo
}

func (gb *GraphBuilder) getUEAndDNGatewayRanges() []*ueDNGatewayRangesInfo {
	if gb.topology == model.FullCore {
		return gb.getFullCoreUEAndDNGatewayRanges()
	}
	return gb.getUPFIsolationUEAndDNGatewayRanges()
}

func (gb *GraphBuilder) getUERangeIPs(ueRange interface{}) []string {
	if gb.topology == model.FullCore {
		return gb.getFullCoreUERangeIPs(ueRange)
	}
	return gb.getUPFIsolationUERangeIPs(ueRange)
}

func (gb *GraphBuilder) getDistributedOrDUTPeer(nodeAgentID string, nodeType, peerNodeType mwapi.LCNodeType) *config.NodeConfig {
	nodeConfig := gb.configsProvider.GetDistributedPeerNodeConfig(
		nodeAgentID, nodeType, peerNodeType,
	)
	if nodeConfig == nil {
		nodeConfig = gb.getDUTNodeConfig(peerNodeType)
		if nodeConfig == nil {
			return nil
		}
	}

	rangeProvider := getNodeRangeProvider(peerNodeType)
	nodeRanges := rangeProvider.getEnabledNodeRanges(nodeConfig.Config)
	if len(nodeRanges) == 0 {
		return nil
	}

	return nodeConfig
}

// For the full core topology, UPF is acting as gateway from DN to UEs.
func (gb *GraphBuilder) getFullCoreUEAndDNGatewayRanges() []*ueDNGatewayRangesInfo {
	rans := gb.configsProvider.GetDistributedNodeConfigs(mwapi.RAN)
	ranges := make([]*ueDNGatewayRangesInfo, 0, len(rans))

	for i := range rans {
		ran := &rans[i]
		ue := gb.getDistributedOrDUTPeer(ran.AgentID, mwapi.RAN, mwapi.UE)
		if ue == nil {
			continue
		}
		amf := gb.getDistributedOrDUTPeer(ran.AgentID, mwapi.RAN, mwapi.AMF)
		if amf == nil {
			continue
		}
		smf := gb.getDistributedOrDUTPeer(amf.AgentID, mwapi.AMF, mwapi.SMF)
		if smf == nil {
			continue
		}
		upf := gb.getDistributedOrDUTPeer(smf.AgentID, mwapi.SMF, mwapi.UPF)
		if upf == nil {
			continue
		}

		rangeProvider := getNodeRangeProvider(mwapi.UE)
		ueRanges := rangeProvider.getEnabledNodeRanges(ue.Config)
		if len(ueRanges) == 0 {
			continue
		}

		rangeProvider = getNodeRangeProvider(mwapi.UPF)
		upfRanges := rangeProvider.getEnabledNodeRanges(upf.Config)
		if len(upfRanges) == 0 {
			continue
		}

		rangesInfo := ueDNGatewayRangesInfo{
			ranAgentID:      ran.AgentID,
			ueRanges:        ueRanges,
			dnGatewayRanges: upfRanges,
		}
		ranges = append(ranges, &rangesInfo)
	}
	return ranges
}

// For the UPF isolation topology, UPF is acting as gateway from DN to UEs.
func (gb *GraphBuilder) getUPFIsolationUEAndDNGatewayRanges() []*ueDNGatewayRangesInfo {
	n4smfs := gb.configsProvider.GetDistributedNodeConfigs(mwapi.N4_SMF)
	ranges := make([]*ueDNGatewayRangesInfo, 0, len(n4smfs))
	for i := range n4smfs {
		n4smf := &n4smfs[i]
		ue := gb.getDistributedOrDUTPeer(n4smf.AgentID, mwapi.N4_SMF, mwapi.UE)
		if ue == nil {
			continue
		}
		upf := gb.getDistributedOrDUTPeer(n4smf.AgentID, mwapi.N4_SMF, mwapi.UPF)
		if upf == nil {
			continue
		}

		rangeProvider := getNodeRangeProvider(mwapi.UE)
		ueRanges := rangeProvider.getEnabledNodeRanges(ue.Config)
		if len(ueRanges) == 0 {
			continue
		}

		rangeProvider = getNodeRangeProvider(mwapi.UPF)
		upfRanges := rangeProvider.getEnabledNodeRanges(upf.Config)
		if len(upfRanges) == 0 {
			continue
		}

		rangesInfo := ueDNGatewayRangesInfo{
			ranAgentID:      n4smf.AgentID,
			ueRanges:        ueRanges,
			dnGatewayRanges: upfRanges,
		}
		ranges = append(ranges, &rangesInfo)
	}
	return ranges
}

func (gb *GraphBuilder) getFullCoreUERangeIPs(ueRange interface{}) []string {
	cfg, ok := gb.globalConfig.(*mwapi.Config)
	if !ok {
		return nil
	}
	ueRangeVal := reflect.ValueOf(ueRange)
	ueDNNsVal := helpers.GetTypedFieldByName(ueRangeVal, "Settings.DnnsConfig", reflect.Slice)
	ueIPs := make([]string, 0, ueDNNsVal.Len())

	for i := 0; i < ueDNNsVal.Len(); i++ {
		ueDNN, ok := ueDNNsVal.Index(i).Interface().(mwapi.UeDnnConfiguration)
		if !ok {
			panic("Invalid type for UE DNN configuration")
		}
		pduType := mwapi.I_PV4

		for j := range cfg.GlobalSettings.Dnns {
			globalDNN := &cfg.GlobalSettings.Dnns[j]
			if ueDNN.Id == globalDNN.Id {
				if globalDNN.PduType != nil && *globalDNN.PduType == mwapi.I_PV6 {
					pduType = mwapi.I_PV6
				}
				break
			}
		}
		if pduType == mwapi.I_PV4 {
			ueIPs = append(ueIPs, ueDNN.IpAddress.Value)
		} else {
			ueIPs = append(ueIPs, ueDNN.Ipv6Address.Value)
		}
	}
	return ueIPs
}

func (gb *GraphBuilder) getUPFIsolationUERangeIPs(ueRange interface{}) []string {
	ueRangeVal := reflect.ValueOf(ueRange)
	identificationVal := helpers.GetFieldByName(ueRangeVal, "Identification")
	ueIPVal := helpers.GetFieldByName(identificationVal, "UeIp")
	ueIPField, ok := ueIPVal.Interface().(mwapi.IdentificationField)
	if !ok {
		panic("Invalid type for UE IP identification field")
	}
	return []string{ueIPField.Value}
}
