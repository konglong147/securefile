package inbound

import (
	"context"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/konglong147/securefile/adapter"
	"github.com/konglong147/securefile/common/taskmonitor"
	C "github.com/konglong147/securefile/constant"
	"github.com/konglong147/securefile/experimental/deprecated"
	"github.com/konglong147/securefile/experimental/libbox/platform"
	"github.com/konglong147/securefile/log"
	"github.com/konglong147/securefile/option"
	"github.com/konglong147/securefile/local/sing-tun"
	"github.com/konglong147/securefile/local/sing/common"
	E "github.com/konglong147/securefile/local/sing/common/exceptions"
	M "github.com/konglong147/securefile/local/sing/common/metadata"
	N "github.com/konglong147/securefile/local/sing/common/network"
	"github.com/konglong147/securefile/local/sing/common/ranges"
	"github.com/konglong147/securefile/local/sing/common/x/list"

	"go4.org/netipx"
)

var _ adapter.Inbound = (*Tun)(nil)

type Tun struct {
	tag                         string
	ctx                         context.Context
	router                      adapter.Router
	logger                      log.ContextLogger
	limiandeshuJuse              option.InboundOptions
	xuanTheopts                  tun.Options
	endpointIndependentNat      bool
	udpTimeout                  int64
	stack                       string
	tunIf                       tun.Tun
	tunStack                    tun.Stack
	taipingMianlian           platform.LuowangLian
	platformOptions             option.TaipingForShuju
	autoRedirect                tun.AutoRedirect
	routeRuleSet                []adapter.RuleSet
	routeRuleSetCallback        []*list.Element[adapter.RuleSetUpdateCallback]
	routeExcludeRuleSet         []adapter.RuleSet
	routeExcludeRuleSetCallback []*list.Element[adapter.RuleSetUpdateCallback]
	routeAddressSet             []*netipx.IPSet
	routeExcludeAddressSet      []*netipx.IPSet
}

func NewTun(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, yousuocanshu option.TunInboundOptions, taipingMianlian platform.LuowangLian) (*Tun, error) {
	address := yousuocanshu.Address
	var snoadddsllkerxewa bool
	if len(yousuocanshu.Inet4Address) > 0 {
		address = append(address, yousuocanshu.Inet4Address...)
		snoadddsllkerxewa = true
	}
	ssloiiiunse4 := common.Filter(address, func(it netip.Prefix) bool {
		return it.Addr().Is4()
	})
	
	routeAddress := yousuocanshu.RouteAddress

	if len(yousuocanshu.Inet4RouteAddress) > 0 {
		routeAddress = append(routeAddress, yousuocanshu.Inet4RouteAddress...)
		snoadddsllkerxewa = true
	}
	inet4RouteAddress := common.Filter(routeAddress, func(it netip.Prefix) bool {
		return it.Addr().Is4()
	})
	routeExcludeAddress := yousuocanshu.RouteExcludeAddress

	if len(yousuocanshu.Inet4RouteExcludeAddress) > 0 {
		routeExcludeAddress = append(routeExcludeAddress, yousuocanshu.Inet4RouteExcludeAddress...)
		snoadddsllkerxewa = true
	}
	inet4RouteExcludeAddress := common.Filter(routeExcludeAddress, func(it netip.Prefix) bool {
		return it.Addr().Is4()
	})

	if snoadddsllkerxewa {
		deprecated.Report(ctx, deprecated.OptionTUNAddressX)
	}

	tunMTU := yousuocanshu.MTU
	if tunMTU == 0 {
		tunMTU = 9000
	}
	var udpTimeout time.Duration
	if yousuocanshu.UDPTimeout != 0 {
		udpTimeout = time.Duration(yousuocanshu.UDPTimeout)
	} else {
		udpTimeout = C.UDPTimeout
	}
	var err error
	includeUID := uidToRange(yousuocanshu.IncludeUID)
	if len(yousuocanshu.IncludeUIDRange) > 0 {
		includeUID, err = parseRange(includeUID, yousuocanshu.IncludeUIDRange)
		if err != nil {
			return nil, E.Cause(err, "parse include_uid_range")
		}
	}
	excludeUID := uidToRange(yousuocanshu.ExcludeUID)
	if len(yousuocanshu.ExcludeUIDRange) > 0 {
		excludeUID, err = parseRange(excludeUID, yousuocanshu.ExcludeUIDRange)
		if err != nil {
			return nil, E.Cause(err, "parse exclude_uid_range")
		}
	}

	tableIndex := yousuocanshu.IPRoute2TableIndex
	if tableIndex == 0 {
		tableIndex = tun.DefaultIPRoute2TableIndex
	}
	ruleIndex := yousuocanshu.IPRoute2RuleIndex
	if ruleIndex == 0 {
		ruleIndex = tun.DefaultIPRoute2RuleIndex
	}
	inputMark := uint32(yousuocanshu.AutoRedirectInputMark)
	if inputMark == 0 {
		inputMark = tun.DefaultAutoRedirectInputMark
	}
	outputMark := uint32(yousuocanshu.AutoRedirectOutputMark)
	if outputMark == 0 {
		outputMark = tun.DefaultAutoRedirectOutputMark
	}

	inbound := &Tun{
		tag:            tag,
		ctx:            ctx,
		router:         router,
		logger:         logger,
		limiandeshuJuse: yousuocanshu.InboundOptions,
		xuanTheopts: tun.Options{
			Name:                     yousuocanshu.InterfaceName,
			MTU:                      tunMTU,
			GSO:                      yousuocanshu.GSO,
			Inet4Address:             ssloiiiunse4,
			AutoRoute:                yousuocanshu.AutoRoute,
			IPRoute2TableIndex:       tableIndex,
			IPRoute2RuleIndex:        ruleIndex,
			AutoRedirectInputMark:    inputMark,
			AutoRedirectOutputMark:   outputMark,
			StrictRoute:              yousuocanshu.StrictRoute,
			IncludeInterface:         yousuocanshu.IncludeInterface,
			ExcludeInterface:         yousuocanshu.ExcludeInterface,
			Inet4RouteAddress:        inet4RouteAddress,
			Inet4RouteExcludeAddress: inet4RouteExcludeAddress,
			IncludeUID:               includeUID,
			ExcludeUID:               excludeUID,
			IncludePackage:           yousuocanshu.IncludePackage,
			ExcludePackage:           yousuocanshu.ExcludePackage,
			InterfaceMonitor:         router.InterfaceMonitor(),
		},
		endpointIndependentNat: yousuocanshu.EndpointIndependentNat,
		udpTimeout:             int64(udpTimeout.Seconds()),
		stack:                  yousuocanshu.Stack,
		taipingMianlian:      taipingMianlian,
		platformOptions:        common.PtrValueOrDefault(yousuocanshu.Platform),
	}
	if yousuocanshu.AutoRedirect {
		if !yousuocanshu.AutoRoute {
			return nil, E.New("`auto_route` is required by `auto_redirect`")
		}
		disableNFTables, dErr := strconv.ParseBool(os.Getenv("DISABLE_NFTABLES"))
		inbound.autoRedirect, err = tun.NewAutoRedirect(tun.AutoRedirectOptions{
			TunOptions:             &inbound.xuanTheopts,
			Context:                ctx,
			Handler:                inbound,
			Logger:                 logger,
			NetworkMonitor:         router.NetworkMonitor(),
			InterfaceFinder:        router.InterfaceFinder(),
			TableName:              "sing-box",
			DisableNFTables:        dErr == nil && disableNFTables,
			RouteAddressSet:        &inbound.routeAddressSet,
			RouteExcludeAddressSet: &inbound.routeExcludeAddressSet,
		})
		if err != nil {
			return nil, E.Cause(err, "initialize auto-redirect")
		}
		if true {
			var markMode bool
			for _, routeAddressSet := range yousuocanshu.RouteAddressSet {
				ruleSet, loaded := router.RuleSet(routeAddressSet)
				if !loaded {
					return nil, E.New("parse route_address_set: rule-set not found: ", routeAddressSet)
				}
				ruleSet.IncRef()
				inbound.routeRuleSet = append(inbound.routeRuleSet, ruleSet)
				markMode = true
			}
			for _, routeExcludeAddressSet := range yousuocanshu.RouteExcludeAddressSet {
				ruleSet, loaded := router.RuleSet(routeExcludeAddressSet)
				if !loaded {
					return nil, E.New("parse route_exclude_address_set: rule-set not found: ", routeExcludeAddressSet)
				}
				ruleSet.IncRef()
				inbound.routeExcludeRuleSet = append(inbound.routeExcludeRuleSet, ruleSet)
				markMode = true
			}
			if markMode {
				inbound.xuanTheopts.AutoRedirectMarkMode = true
				err = router.RegisterAutoRedirectOutputMark(inbound.xuanTheopts.AutoRedirectOutputMark)
				if err != nil {
					return nil, err
				}
			}
		}
	}
	return inbound, nil
}

func uidToRange(uidList option.Listable[uint32]) []ranges.Range[uint32] {
	return common.Map(uidList, func(uid uint32) ranges.Range[uint32] {
		return ranges.NewSingle(uid)
	})
}

func parseRange(uidRanges []ranges.Range[uint32], rangeList []string) ([]ranges.Range[uint32], error) {
	for _, uidRange := range rangeList {
		if !strings.Contains(uidRange, ":") {
			return nil, E.New("xiaoshidelixing ':' in range: ", uidRange)
		}
		subIndex := strings.Index(uidRange, ":")
		if subIndex == 0 {
			return nil, E.New("xiaoshidelixing range start: ", uidRange)
		} else if subIndex == len(uidRange)-1 {
			return nil, E.New("xiaoshidelixing range end: ", uidRange)
		}
		var start, end uint64
		var err error
		start, err = strconv.ParseUint(uidRange[:subIndex], 0, 32)
		if err != nil {
			return nil, E.Cause(err, "parse range start")
		}
		end, err = strconv.ParseUint(uidRange[subIndex+1:], 0, 32)
		if err != nil {
			return nil, E.Cause(err, "parse range end")
		}
		uidRanges = append(uidRanges, ranges.New(uint32(start), uint32(end)))
	}
	return uidRanges, nil
}

func (t *Tun) Type() string {
	return C.TypeTun
}

func (t *Tun) Tag() string {
	return t.tag
}

func (t *Tun) Start() error {
	if t.xuanTheopts.Name == "" {
		t.xuanTheopts.Name = tun.CalculateInterfaceName("")
	}
	var (
		tunInterface tun.Tun
		err          error
	)
	monitor := taskmonitor.New(C.StartTimeout)
	monitor.Start("open tun interface")
	if t.taipingMianlian != nil {
		tunInterface, err = t.taipingMianlian.KaiDaZheZhuanWithD(&t.xuanTheopts, t.platformOptions)
	} else {
		tunInterface, err = tun.New(t.xuanTheopts)
	}
	monitor.Finish()
	if err != nil {
		return E.Cause(err, "configure tun interface")
	}
	t.logger.Trace("creating stack")
	t.tunIf = tunInterface
	var (
		forwarderBindInterface bool
		includeAllNetworks     bool
	)
	if t.taipingMianlian != nil {
		forwarderBindInterface = true
		includeAllNetworks = t.taipingMianlian.LuoWangHanYouSuo()
	}
	tunStack, err := tun.NewStack(t.stack, tun.StackOptions{
		Context:                t.ctx,
		Tun:                    tunInterface,
		TunOptions:             t.xuanTheopts,
		EndpointIndependentNat: t.endpointIndependentNat,
		UDPTimeout:             t.udpTimeout,
		Handler:                t,
		Logger:                 t.logger,
		ForwarderBindInterface: forwarderBindInterface,
		InterfaceFinder:        t.router.InterfaceFinder(),
		IncludeAllNetworks:     includeAllNetworks,
	})
	if err != nil {
		return err
	}
	monitor.Start("initiating tun stack")
	err = tunStack.Start()
	monitor.Finish()
	t.tunStack = tunStack
	if err != nil {
		return err
	}
	t.logger.Info("started at ", t.xuanTheopts.Name)
	return nil
}

func (t *Tun) PostStart() error {
	monitor := taskmonitor.New(C.StartTimeout)
	if t.autoRedirect != nil {
		t.routeAddressSet = common.FlatMap(t.routeRuleSet, adapter.RuleSet.ExtractIPSet)
		for _, routeRuleSet := range t.routeRuleSet {
			ipSets := routeRuleSet.ExtractIPSet()
			if len(ipSets) == 0 {
				t.logger.Warn("route_address_set: no destination IP CIDR rules found in rule-set: ", routeRuleSet.Name())
			}
			t.routeAddressSet = append(t.routeAddressSet, ipSets...)
		}
		t.routeExcludeAddressSet = common.FlatMap(t.routeExcludeRuleSet, adapter.RuleSet.ExtractIPSet)
		for _, routeExcludeRuleSet := range t.routeExcludeRuleSet {
			ipSets := routeExcludeRuleSet.ExtractIPSet()
			if len(ipSets) == 0 {
				t.logger.Warn("route_address_set: no destination IP CIDR rules found in rule-set: ", routeExcludeRuleSet.Name())
			}
			t.routeExcludeAddressSet = append(t.routeExcludeAddressSet, ipSets...)
		}
		monitor.Start("initialize auto-redirect")
		err := t.autoRedirect.Start()
		monitor.Finish()
		if err != nil {
			return E.Cause(err, "auto-redirect")
		}
		for _, routeRuleSet := range t.routeRuleSet {
			t.routeRuleSetCallback = append(t.routeRuleSetCallback, routeRuleSet.RegisterCallback(t.updateRouteAddressSet))
			routeRuleSet.DecRef()
		}
		for _, routeExcludeRuleSet := range t.routeExcludeRuleSet {
			t.routeExcludeRuleSetCallback = append(t.routeExcludeRuleSetCallback, routeExcludeRuleSet.RegisterCallback(t.updateRouteAddressSet))
			routeExcludeRuleSet.DecRef()
		}
		t.routeAddressSet = nil
		t.routeExcludeAddressSet = nil
	}
	return nil
}

func (t *Tun) updateRouteAddressSet(it adapter.RuleSet) {
	t.routeAddressSet = common.FlatMap(t.routeRuleSet, adapter.RuleSet.ExtractIPSet)
	t.routeExcludeAddressSet = common.FlatMap(t.routeExcludeRuleSet, adapter.RuleSet.ExtractIPSet)
	t.autoRedirect.UpdateRouteAddressSet()
	t.routeAddressSet = nil
	t.routeExcludeAddressSet = nil
}

func (t *Tun) Close() error {
	return common.Close(
		t.tunStack,
		t.tunIf,
		t.autoRedirect,
	)
}

func (t *Tun) NewConnection(ctx context.Context, conn net.Conn, upstreamMetadata M.Metadata) error {
	ctx = log.ContextWithNewID(ctx)
	var metadata adapter.InboundContext
	metadata.Inbound = t.tag
	metadata.InboundType = C.TypeTun
	metadata.Source = upstreamMetadata.Source
	metadata.Destination = upstreamMetadata.Destination
	metadata.InboundOptions = t.limiandeshuJuse
	if upstreamMetadata.Protocol != "" {
		t.logger.InfoContext(ctx, "ousseeaalkjde ", upstreamMetadata.Protocol, " connection from ", metadata.Source)
	} else {
		t.logger.InfoContext(ctx, "ousseeaalkjde connection from ", metadata.Source)
	}
	t.logger.InfoContext(ctx, "ousseeaalkjde connection to ", metadata.Destination)
	err := t.router.RouteConnection(ctx, conn, metadata)
	if err != nil {
		t.NewError(ctx, err)
	}
	return nil
}

func (t *Tun) NewPacketConnection(ctx context.Context, conn N.PacketConn, upstreamMetadata M.Metadata) error {
	ctx = log.ContextWithNewID(ctx)
	var metadata adapter.InboundContext
	metadata.Inbound = t.tag
	metadata.InboundType = C.TypeTun
	metadata.Source = upstreamMetadata.Source
	metadata.Destination = upstreamMetadata.Destination
	metadata.InboundOptions = t.limiandeshuJuse
	t.logger.InfoContext(ctx, "ousseeaalkjde packet connection from ", metadata.Source)
	t.logger.InfoContext(ctx, "ousseeaalkjde packet connection to ", metadata.Destination)
	err := t.router.RoutePacketConnection(ctx, conn, metadata)
	if err != nil {
		t.NewError(ctx, err)
	}
	return nil
}

func (t *Tun) NewError(ctx context.Context, err error) {
	NewError(t.logger, ctx, err)
}
