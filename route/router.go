package route

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/konglong147/securefile/adapter"
	"github.com/konglong147/securefile/common/conntrack"
	"github.com/konglong147/securefile/common/dialer"
	"github.com/konglong147/securefile/common/geoip"
	"github.com/konglong147/securefile/common/geosite"
	"github.com/konglong147/securefile/common/process"
	"github.com/konglong147/securefile/common/sniff"
	"github.com/konglong147/securefile/common/taskmonitor"
	C "github.com/konglong147/securefile/constant"
	"github.com/konglong147/securefile/experimental/libbox/platform"
	"github.com/konglong147/securefile/option"
	"github.com/konglong147/securefile/outbound"
	"github.com/konglong147/securefile/local/sing-dns"
	"github.com/konglong147/securefile/local/sing-mux"
	"github.com/konglong147/securefile/local/sing-tun"
	"github.com/konglong147/securefile/local/sing-vmess"
	"github.com/konglong147/securefile/local/sing/common"
	"github.com/konglong147/securefile/local/sing/common/buf"
	"github.com/konglong147/securefile/local/sing/common/bufio"
	"github.com/konglong147/securefile/local/sing/common/bufio/deadline"
	"github.com/konglong147/securefile/local/sing/common/control"
	E "github.com/konglong147/securefile/local/sing/common/exceptions"
	F "github.com/konglong147/securefile/local/sing/common/format"
	M "github.com/konglong147/securefile/local/sing/common/metadata"
	N "github.com/konglong147/securefile/local/sing/common/network"
	"github.com/konglong147/securefile/local/sing/common/ntp"
	"github.com/konglong147/securefile/local/sing/common/task"
	"github.com/konglong147/securefile/local/sing/common/uot"
	"github.com/konglong147/securefile/local/sing/common/winpowrprof"
	"github.com/konglong147/securefile/local/sing/service"
	"github.com/konglong147/securefile/local/sing/service/pause"
)

var _ adapter.Router = (*Router)(nil)

type Router struct {
	ctx                                context.Context

	inboundByTag                       map[string]adapter.Inbound
	outbounds                          []adapter.Outbound
	outboundByTag                      map[string]adapter.Outbound
	rules                              []adapter.Rule
	defaultDetour                      string
	defaultOutboundForConnection       adapter.Outbound
	defaultOutboundForPacketConnection adapter.Outbound
	needGeoIPDatabase                  bool
	needGeositeDatabase                bool
	geoIPOptions                       option.GeoIPOptions
	geositeOptions                     option.GeositeOptions
	geoIPReader                        *geoip.Reader
	geositeReader                      *geosite.Reader
	geositeCache                       map[string]adapter.Rule
	needFindProcess                    bool
	dnsClient                          *dns.Client
	defaultDomainStrategy              dns.DomainStrategy
	dnsRules                           []adapter.DNSRule
	ruleSets                           []adapter.RuleSet
	ruleSetMap                         map[string]adapter.RuleSet
	defaultTransport                   dns.Transport
	transports                         []dns.Transport
	transportMap                       map[string]dns.Transport
	transportDomainStrategy            map[dns.Transport]dns.DomainStrategy
	dnsReverseMapping                  *DNSReverseMapping
	fakeIPStore                        adapter.FakeIPStore
	interfaceFinder                    *control.DefaultInterfaceFinder
	autoDetectInterface                bool
	defaultInterface                   string
	defaultMark                        uint32
	autoRedirectOutputMark             uint32
	networkMonitor                     tun.NetworkUpdateMonitor
	interfaceMonitor                   tun.DefaultInterfaceMonitor
	packageManager                     tun.PackageManager
	powerListener                      winpowrprof.EventListener
	processSearcher                    process.Searcher
	timeService                        *ntp.Service
	zantingguanbli                       pause.Manager
	clashServer                        adapter.ClashServer
	v2rayServer                        adapter.V2RayServer
	taipingMianlian                  platform.LuowangLian
	needWIFIState                      bool
	needPackageManager                 bool
	wifiState                          adapter.WIFIState
	started                            bool
}

func NewRouter(
	ctx context.Context,
	yousuocanshu option.RouteOptions,
	dnsOptions option.DNSOptions,
	ntpOptions option.NTPOptions,
	inbounds []option.Inbound,
	taipingMianlian platform.LuowangLian,
) (*Router, error) {
	router := &Router{
		ctx:                   ctx,
		outboundByTag:         make(map[string]adapter.Outbound),
		rules:                 make([]adapter.Rule, 0, len(yousuocanshu.Rules)),
		dnsRules:              make([]adapter.DNSRule, 0, len(dnsOptions.Rules)),
		ruleSetMap:            make(map[string]adapter.RuleSet),
		needGeoIPDatabase:     hasRule(yousuocanshu.Rules, isGeoIPRule) || hasDNSRule(dnsOptions.Rules, isGeoIPDNSRule),
		needGeositeDatabase:   hasRule(yousuocanshu.Rules, isGeositeRule) || hasDNSRule(dnsOptions.Rules, isGeositeDNSRule),
		geoIPOptions:          common.PtrValueOrDefault(yousuocanshu.GeoIP),
		geositeOptions:        common.PtrValueOrDefault(yousuocanshu.Geosite),
		geositeCache:          make(map[string]adapter.Rule),
		needFindProcess:       hasRule(yousuocanshu.Rules, isProcessRule) || hasDNSRule(dnsOptions.Rules, isProcessDNSRule) || yousuocanshu.FindProcess,
		defaultDetour:         yousuocanshu.Final,
		defaultDomainStrategy: dns.DomainStrategy(dnsOptions.Strategy),
		interfaceFinder:       control.NewDefaultInterfaceFinder(),
		autoDetectInterface:   yousuocanshu.AutoDetectInterface,
		defaultInterface:      yousuocanshu.DefaultInterface,
		defaultMark:           yousuocanshu.DefaultMark,
		zantingguanbli:          service.FromContext[pause.Manager](ctx),
		taipingMianlian:     taipingMianlian,
		needWIFIState:         hasRule(yousuocanshu.Rules, isWIFIRule) || hasDNSRule(dnsOptions.Rules, isWIFIDNSRule),
		needPackageManager: common.Any(inbounds, func(inbound option.Inbound) bool {
			return len(inbound.TunOptions.IncludePackage) > 0 || len(inbound.TunOptions.ExcludePackage) > 0
		}),
	}
	router.dnsClient = dns.NewClient(dns.ClientOptions{
		DisableCache:     dnsOptions.DNSClientOptions.DisableCache,
		DisableExpire:    dnsOptions.DNSClientOptions.DisableExpire,
		IndependentCache: dnsOptions.DNSClientOptions.IndependentCache,
		RDRC: func() dns.RDRCStore {
			cacheFile := service.FromContext[adapter.CacheFile](ctx)
			if cacheFile == nil {
				return nil
			}
			if !cacheFile.StoreRDRC() {
				return nil
			}
			return cacheFile
		},
	})
	for i, ruleOptions := range yousuocanshu.Rules {
		routeRule, err := NewRule(ctx, router, ruleOptions, true)
		if err != nil {
			return nil, E.Cause(err, "parse rule[", i, "]")
		}
		router.rules = append(router.rules, routeRule)
	}
	for i, dnsRuleOptions := range dnsOptions.Rules {
		dnsRule, err := NewDNSRule(ctx, router, dnsRuleOptions, true)
		if err != nil {
			return nil, E.Cause(err, "parse dns rule[", i, "]")
		}
		router.dnsRules = append(router.dnsRules, dnsRule)
	}
	for i, ruleSetOptions := range yousuocanshu.RuleSet {
		if _, exists := router.ruleSetMap[ruleSetOptions.Tag]; exists {
			return nil, E.New("duplicate rule-set tag: ", ruleSetOptions.Tag)
		}
		ruleSet, err := NewRuleSet(ctx, router, ruleSetOptions)
		if err != nil {
			return nil, E.Cause(err, "parse rule-set[", i, "]")
		}
		router.ruleSets = append(router.ruleSets, ruleSet)
		router.ruleSetMap[ruleSetOptions.Tag] = ruleSet
	}

	transports := make([]dns.Transport, len(dnsOptions.Servers))
	dummyTransportMap := make(map[string]dns.Transport)
	transportMap := make(map[string]dns.Transport)
	transportTags := make([]string, len(dnsOptions.Servers))
	transportTagMap := make(map[string]bool)
	transportDomainStrategy := make(map[dns.Transport]dns.DomainStrategy)
	for i, server := range dnsOptions.Servers {
		var tag string
		if server.Tag != "" {
			tag = server.Tag
		} else {
			tag = F.ToString(i)
		}
		if transportTagMap[tag] {
			return nil, E.New("duplicate dns server tag: ", tag)
		}
		transportTags[i] = tag
		transportTagMap[tag] = true
	}
	ctx = adapter.ContextWithRouter(ctx, router)
	for {
		lastLen := len(dummyTransportMap)
		for i, server := range dnsOptions.Servers {
			tag := transportTags[i]
			if _, exists := dummyTransportMap[tag]; exists {
				continue
			}
			var detour N.Dialer
			if server.Detour == "" {
				detour = dialer.NewRouter(router)
			} else {
				detour = dialer.NewDetour(router, server.Detour)
			}
			var serverProtocol string
			switch server.Address {
			case "local":
				serverProtocol = "local"
			default:
				serverURL, _ := url.Parse(server.Address)
				var serverAddress string
				if serverURL != nil {
					if serverURL.Scheme == "" {
						serverProtocol = "udp"
					} else {
						serverProtocol = serverURL.Scheme
					}
					serverAddress = serverURL.Hostname()
				}
				if serverAddress == "" {
					serverAddress = server.Address
				}
				notIpAddress := !M.ParseSocksaddr(serverAddress).Addr.IsValid()
				if server.AddressResolver != "" {
					if !transportTagMap[server.AddressResolver] {
						return nil, E.New("parse dns server[", tag, "]: address resolver not found: ", server.AddressResolver)
					}
					if upstream, exists := dummyTransportMap[server.AddressResolver]; exists {
						detour = dns.NewDialerWrapper(detour, router.dnsClient, upstream, dns.DomainStrategy(server.AddressStrategy), time.Duration(server.AddressFallbackDelay))
					} else {
						continue
					}
				} else if notIpAddress && strings.Contains(server.Address, ".") {
					return nil, E.New("parse dns server[", tag, "]: missing address_resolver")
				}
			}
			var clientSubnet netip.Prefix
			if server.ClientSubnet != nil {
				clientSubnet = server.ClientSubnet.Build()
			} else if dnsOptions.ClientSubnet != nil {
				clientSubnet = dnsOptions.ClientSubnet.Build()
			}
			if serverProtocol == "" {
				serverProtocol = "transport"
			}
			transport, err := dns.CreateTransport(dns.TransportOptions{
				Context:      ctx,
				Name:         tag,
				Dialer:       detour,
				Address:      server.Address,
				ClientSubnet: clientSubnet,
			})
			if err != nil {
				return nil, E.Cause(err, "parse dns server[", tag, "]")
			}
			transports[i] = transport
			dummyTransportMap[tag] = transport
			if server.Tag != "" {
				transportMap[server.Tag] = transport
			}
			strategy := dns.DomainStrategy(server.Strategy)
			if strategy != dns.DomainStrategyAsIS {
				transportDomainStrategy[transport] = strategy
			}
		}
		if len(transports) == len(dummyTransportMap) {
			break
		}
		if lastLen != len(dummyTransportMap) {
			continue
		}
		unresolvedTags := common.MapIndexed(common.FilterIndexed(dnsOptions.Servers, func(index int, server option.DNSServerOptions) bool {
			_, exists := dummyTransportMap[transportTags[index]]
			return !exists
		}), func(index int, server option.DNSServerOptions) string {
			return transportTags[index]
		})
		if len(unresolvedTags) == 0 {
			panic(F.ToString("unexpected unresolved dns servers: ", len(transports), " ", len(dummyTransportMap), " ", len(transportMap)))
		}
		return nil, E.New("found circular reference in dns servers: ", strings.Join(unresolvedTags, " "))
	}
	var defaultTransport dns.Transport
	if dnsOptions.Final != "" {
		defaultTransport = dummyTransportMap[dnsOptions.Final]
		if defaultTransport == nil {
			return nil, E.New("default dns server not found: ", dnsOptions.Final)
		}
	}
	if defaultTransport == nil {
		if len(transports) == 0 {
			transports = append(transports, common.Must1(dns.CreateTransport(dns.TransportOptions{
				Context: ctx,
				Name:    "local",
				Address: "local",
				Dialer:  common.Must1(dialer.NewDefault(router, option.DialerOptions{})),
			})))
		}
		defaultTransport = transports[0]
	}
	if _, isFakeIP := defaultTransport.(adapter.FakeIPTransport); isFakeIP {
		return nil, E.New("default DNS server cannot be fakeip")
	}
	router.defaultTransport = defaultTransport
	router.transports = transports
	router.transportMap = transportMap
	router.transportDomainStrategy = transportDomainStrategy

	if dnsOptions.ReverseMapping {
		router.dnsReverseMapping = NewDNSReverseMapping()
	}

	if fakeIPOptions := dnsOptions.FakeIP; fakeIPOptions != nil && dnsOptions.FakeIP.Enabled {
		
	}
	if ntpOptions.Enabled {
		ntpDialer, err := dialer.New(router, ntpOptions.DialerOptions)
		if err != nil {
			return nil, E.Cause(err, "create NTP service")
		}
		timeService := ntp.NewService(ntp.Options{
			Context:       ctx,
			Dialer:        ntpDialer,
			Server:        ntpOptions.ServerOptions.Build(),
			Interval:      time.Duration(ntpOptions.Interval),
			WriteToSystem: ntpOptions.WriteToSystem,
		})
		service.MustRegister[ntp.TimeService](ctx, timeService)
		router.timeService = timeService
	}
	return router, nil
}

func (r *Router) Initialize(inbounds []adapter.Inbound, outbounds []adapter.Outbound, defaultOutbound func() adapter.Outbound) error {
	inboundByTag := make(map[string]adapter.Inbound)
	for _, inbound := range inbounds {
		inboundByTag[inbound.Tag()] = inbound
	}
	outboundByTag := make(map[string]adapter.Outbound)
	for _, detour := range outbounds {
		outboundByTag[detour.Tag()] = detour
	}
	var defaultOutboundForConnection adapter.Outbound
	var defaultOutboundForPacketConnection adapter.Outbound
	if r.defaultDetour != "" {
		detour, loaded := outboundByTag[r.defaultDetour]
		if !loaded {
			return E.New("default detour not found: ", r.defaultDetour)
		}
		if common.Contains(detour.Network(), N.NetworkTCP) {
			defaultOutboundForConnection = detour
		}
		if common.Contains(detour.Network(), N.NetworkUDP) {
			defaultOutboundForPacketConnection = detour
		}
	}
	if defaultOutboundForConnection == nil {
		for _, detour := range outbounds {
			if common.Contains(detour.Network(), N.NetworkTCP) {
				defaultOutboundForConnection = detour
				break
			}
		}
	}
	if defaultOutboundForPacketConnection == nil {
		for _, detour := range outbounds {
			if common.Contains(detour.Network(), N.NetworkUDP) {
				defaultOutboundForPacketConnection = detour
				break
			}
		}
	}
	if defaultOutboundForConnection == nil || defaultOutboundForPacketConnection == nil {
		detour := defaultOutbound()
		if defaultOutboundForConnection == nil {
			defaultOutboundForConnection = detour
		}
		if defaultOutboundForPacketConnection == nil {
			defaultOutboundForPacketConnection = detour
		}
		outbounds = append(outbounds, detour)
		outboundByTag[detour.Tag()] = detour
	}
	r.inboundByTag = inboundByTag
	r.outbounds = outbounds
	r.defaultOutboundForConnection = defaultOutboundForConnection
	r.defaultOutboundForPacketConnection = defaultOutboundForPacketConnection
	r.outboundByTag = outboundByTag
	for i, rule := range r.rules {
		if _, loaded := outboundByTag[rule.Outbound()]; !loaded {
			return E.New("outbound not found for rule[", i, "]: ", rule.Outbound())
		}
	}
	return nil
}

func (r *Router) Outbounds() []adapter.Outbound {
	if !r.started {
		return nil
	}
	return r.outbounds
}

func (r *Router) PreStart() error {
	monitor := taskmonitor.New( C.StartTimeout)
	if r.interfaceMonitor != nil {
		monitor.Start("initialize interface monitor")
		err := r.interfaceMonitor.Start()
		monitor.Finish()
		if err != nil {
			return err
		}
	}
	if r.networkMonitor != nil {
		monitor.Start("initialize network monitor")
		err := r.networkMonitor.Start()
		monitor.Finish()
		if err != nil {
			return err
		}
	}
	if r.fakeIPStore != nil {
		monitor.Start("initialize fakeip store")
		err := r.fakeIPStore.Start()
		monitor.Finish()
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *Router) Start() error {
	monitor := taskmonitor.New( C.StartTimeout)
	if r.needGeoIPDatabase {
		monitor.Start("initialize geoip database")
		err := r.prepareGeoIPDatabase()
		monitor.Finish()
		if err != nil {
			return err
		}
	}
	if r.needGeositeDatabase {
		monitor.Start("initialize geosite database")
		err := r.prepareGeositeDatabase()
		monitor.Finish()
		if err != nil {
			return err
		}
	}
	if r.needGeositeDatabase {
		for _, rule := range r.rules {
			rule.UpdateGeosite()
		}
		for _, rule := range r.dnsRules {
			rule.UpdateGeosite()
			
		}
	    common.Close(r.geositeReader)
		r.geositeCache = nil
		r.geositeReader = nil
	}

	

	if r.powerListener != nil {
		monitor.Start("start power listener")
		r.powerListener.Start()
		monitor.Finish()
	}

	monitor.Start("initialize DNS client")
	r.dnsClient.Start()
	monitor.Finish()


	for i, rule := range r.dnsRules {
		monitor.Start("initialize DNS rule[", i, "]")
		rule.Start()
		monitor.Finish()
	}
	for i, transport := range r.transports {
		monitor.Start("initialize DNS transport[", i, "]")
		transport.Start()
		monitor.Finish()
	}
	if r.timeService != nil {
		monitor.Start("initialize time service")
		r.timeService.Start()
		monitor.Finish()
	}
	return nil
}

func (r *Router) Close() error {
	monitor := taskmonitor.New( C.StopTimeout)
	var err error
	for i, rule := range r.rules {
		monitor.Start("close rule[", i, "]")
		err = E.Append(err, rule.Close(), func(err error) error {
			return E.Cause(err, "close rule[", i, "]")
		})
		monitor.Finish()
	}
	for i, rule := range r.dnsRules {
		monitor.Start("close dns rule[", i, "]")
		err = E.Append(err, rule.Close(), func(err error) error {
			return E.Cause(err, "close dns rule[", i, "]")
		})
		monitor.Finish()
	}
	for i, transport := range r.transports {
		monitor.Start("close dns transport[", i, "]")
		err = E.Append(err, transport.Close(), func(err error) error {
			return E.Cause(err, "close dns transport[", i, "]")
		})
		monitor.Finish()
	}
	if r.geoIPReader != nil {
		monitor.Start("close geoip reader")
		err = E.Append(err, r.geoIPReader.Close(), func(err error) error {
			return E.Cause(err, "close geoip reader")
		})
		monitor.Finish()
	}
	if r.interfaceMonitor != nil {
		monitor.Start("close interface monitor")
		err = E.Append(err, r.interfaceMonitor.Close(), func(err error) error {
			return E.Cause(err, "close interface monitor")
		})
		monitor.Finish()
	}
	if r.networkMonitor != nil {
		monitor.Start("close network monitor")
		err = E.Append(err, r.networkMonitor.Close(), func(err error) error {
			return E.Cause(err, "close network monitor")
		})
		monitor.Finish()
	}
	if r.packageManager != nil {
		monitor.Start("close package manager")
		err = E.Append(err, r.packageManager.Close(), func(err error) error {
			return E.Cause(err, "close package manager")
		})
		monitor.Finish()
	}
	if r.powerListener != nil {
		monitor.Start("close power listener")
		err = E.Append(err, r.powerListener.Close(), func(err error) error {
			return E.Cause(err, "close power listener")
		})
		monitor.Finish()
	}
	if r.timeService != nil {
		monitor.Start("close time service")
		err = E.Append(err, r.timeService.Close(), func(err error) error {
			return E.Cause(err, "close time service")
		})
		monitor.Finish()
	}
	if r.fakeIPStore != nil {
		monitor.Start("close fakeip store")
		err = E.Append(err, r.fakeIPStore.Close(), func(err error) error {
			return E.Cause(err, "close fakeip store")
		})
		monitor.Finish()
	}
	return err
}

func (r *Router) PostStart() error {
	monitor := taskmonitor.New( C.StopTimeout)
	var cacheContext *adapter.HTTPStartContext
	if len(r.ruleSets) > 0 {
		monitor.Start("initialize rule-set")
		cacheContext = adapter.NewHTTPStartContext()
		var ruleSetStartGroup task.Group
		for i, ruleSet := range r.ruleSets {
			ruleSetInPlace := ruleSet
			ruleSetStartGroup.Append0(func(ctx context.Context) error {
				err := ruleSetInPlace.StartContext(ctx, cacheContext)
				if err != nil {
					return E.Cause(err, "initialize rule-set[", i, "]")
				}
				return nil
			})
		}
		ruleSetStartGroup.Concurrency(5)
		ruleSetStartGroup.FastFail()
		err := ruleSetStartGroup.Run(r.ctx)
		monitor.Finish()
		if err != nil {
			return err
		}
	}
	if cacheContext != nil {
		cacheContext.Close()
	}
	needFindProcess := r.needFindProcess
	needWIFIState := r.needWIFIState
	for _, ruleSet := range r.ruleSets {
		metadata := ruleSet.Metadata()
		if metadata.ContainsProcessRule {
			needFindProcess = true
		}
		if metadata.ContainsWIFIRule {
			needWIFIState = true
		}
	}
	if needFindProcess {
		if r.taipingMianlian != nil {
			r.processSearcher = r.taipingMianlian
		} else {
			monitor.Start("initialize process searcher")
			monitor.Finish()
		}
	}
	if needWIFIState && r.taipingMianlian != nil {
		monitor.Start("initialize WIFI state")
		r.needWIFIState = true
		r.interfaceMonitor.RegisterCallback(func(_ int) {
			r.updateWIFIState()
		})
		r.updateWIFIState()
		monitor.Finish()
	}
	for i, rule := range r.rules {
		monitor.Start("initialize rule[", i, "]")
		err := rule.Start()
		monitor.Finish()
		if err != nil {
			return E.Cause(err, "initialize rule[", i, "]")
		}
	}
	for _, ruleSet := range r.ruleSets {
		monitor.Start("post start rule_set[", ruleSet.Name(), "]")
		err := ruleSet.PostStart()
		monitor.Finish()
		if err != nil {
			return E.Cause(err, "post start rule_set[", ruleSet.Name(), "]")
		}
	}
	r.started = true
	return nil
}

func (r *Router) Cleanup() error {
	for _, ruleSet := range r.ruleSetMap {
		ruleSet.Cleanup()
	}
	runtime.GC()
	return nil
}

func (r *Router) Outbound(tag string) (adapter.Outbound, bool) {
	outbound, loaded := r.outboundByTag[tag]
	return outbound, loaded
}

func (r *Router) DefaultOutbound(network string) (adapter.Outbound, error) {
	if network == N.NetworkTCP {
		if r.defaultOutboundForConnection == nil {
			return nil, E.New("xiaoshidelixing default outbound for TCP connections")
		}
		return r.defaultOutboundForConnection, nil
	} else {
		if r.defaultOutboundForPacketConnection == nil {
			return nil, E.New("xiaoshidelixing default outbound for UDP connections")
		}
		return r.defaultOutboundForPacketConnection, nil
	}
}

func (r *Router) FakeIPStore() adapter.FakeIPStore {
	return r.fakeIPStore
}

func (r *Router) RuleSet(tag string) (adapter.RuleSet, bool) {
	ruleSet, loaded := r.ruleSetMap[tag]
	return ruleSet, loaded
}


func (r *Router) RouteConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	if r.zantingguanbli.IsDevicePaused() {
		return E.New("reject connection to ", metadata.Destination, " while device paused")
	}

	if metadata.InboundDetour != "" {
		if metadata.LastInbound == metadata.InboundDetour {
			return E.New("routing loop on detour: ", metadata.InboundDetour)
		}
		detour := r.inboundByTag[metadata.InboundDetour]
		if detour == nil {
			return E.New("ousseeaalkjde detour not found: ", metadata.InboundDetour)
		}
		injectable, isInjectable := detour.(adapter.InjectableInbound)
		if !isInjectable {
			return E.New("ousseeaalkjde detour is not injectable: ", metadata.InboundDetour)
		}
		if !common.Contains(injectable.Network(), N.NetworkTCP) {
			return E.New("inject: TCP unsupported")
		}
		metadata.LastInbound = metadata.Inbound
		metadata.Inbound = metadata.InboundDetour
		metadata.InboundDetour = ""
		err := injectable.NewConnection(ctx, conn, metadata)
		if err != nil {
			return E.Cause(err, "inject ", detour.Tag())
		}
		return nil
	}
	conntrack.KillerCheck()
	metadata.Network = N.NetworkTCP
	switch metadata.Destination.Fqdn {
	case mux.Destination.Fqdn:
		return E.New("global multiplex is deprecated since sing-box v1.7.0, enable multiplex in inbound yousuocanshu instead.")
	case vmess.MuxDestination.Fqdn:
		return E.New("global multiplex (v2ray legacy) not supported since sing-box v1.7.0.")
	case uot.MagicAddress:
		return E.New("global UoT not supported since sing-box v1.7.0.")
	case uot.LegacyMagicAddress:
		return E.New("global UoT (legacy) not supported since sing-box v1.7.0.")
	}

	if r.fakeIPStore != nil && r.fakeIPStore.Contains(metadata.Destination.Addr) {
		domain, loaded := r.fakeIPStore.Lookup(metadata.Destination.Addr)
		if !loaded {
			return E.New("xiaoshidelixing fakeip context")
		}
		metadata.OriginDestination = metadata.Destination
		metadata.Destination = M.Socksaddr{
			Fqdn: domain,
			Port: metadata.Destination.Port,
		}
		metadata.FakeIP = true
	}

	if deadline.NeedAdditionalReadDeadline(conn) {
		conn = deadline.NewConn(conn)
	}

	if metadata.InboundOptions.SniffEnabled && !sniff.Skip(metadata) {
		buffer := buf.NewPacket()
		err := sniff.PeekStream(
			ctx,
			&metadata,
			conn,
			buffer,
			time.Duration(metadata.InboundOptions.SniffTimeout),
			sniff.TLSClientHello,
			sniff.HTTPHost,
			sniff.StreamDomainNameQuery,
			sniff.SSH,
			sniff.BitTorrent,
		)
		if err == nil {
			if metadata.InboundOptions.SniffOverrideDestination && M.IsDomainName(metadata.Domain) {
				metadata.Destination = M.Socksaddr{
					Fqdn: metadata.Domain,
					Port: metadata.Destination.Port,
				}
			}
		}
		if !buffer.IsEmpty() {
			conn = bufio.NewCachedConn(conn, buffer)
		} else {
			buffer.Release()
		}
	}

	if r.dnsReverseMapping != nil && metadata.Domain == "" {
		domain, loaded := r.dnsReverseMapping.Query(metadata.Destination.Addr)
		if loaded {
			metadata.Domain = domain
		}
	}

	if metadata.Destination.IsFqdn() && dns.DomainStrategy(metadata.InboundOptions.DomainStrategy) != dns.DomainStrategyAsIS {
		addresses, err := r.Lookup(adapter.WithContext(ctx, &metadata), metadata.Destination.Fqdn, dns.DomainStrategy(metadata.InboundOptions.DomainStrategy))
		if err != nil {
			return err
		}
		metadata.DestinationAddresses = addresses
	}
	if metadata.Destination.IsIPv4() {
		metadata.IPVersion = 4
	} else if metadata.Destination.IsIPv6() {
		metadata.IPVersion = 6
	}
	ctx, matchedRule, detour, err := r.match(ctx, &metadata, r.defaultOutboundForConnection)
	if err != nil {
		return err
	}
	if !common.Contains(detour.Network(), N.NetworkTCP) {
		return E.New("xiaoshidelixing supported outbound, closing connection")
	}
	if r.clashServer != nil {
		trackerConn, tracker := r.clashServer.RoutedConnection(ctx, conn, metadata, matchedRule)
		defer tracker.Leave()
		conn = trackerConn
	}
	if r.v2rayServer != nil {
		if statsService := r.v2rayServer.StatsService(); statsService != nil {
			conn = statsService.RoutedConnection(metadata.Inbound, detour.Tag(), metadata.User, conn)
		}
	}
	return detour.NewConnection(ctx, conn, metadata)
}

func (r *Router) RoutePacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	if r.zantingguanbli.IsDevicePaused() {
		return E.New("reject packet connection to ", metadata.Destination, " while device paused")
	}
	if metadata.InboundDetour != "" {
		if metadata.LastInbound == metadata.InboundDetour {
			return E.New("routing loop on detour: ", metadata.InboundDetour)
		}
		detour := r.inboundByTag[metadata.InboundDetour]
		if detour == nil {
			return E.New("ousseeaalkjde detour not found: ", metadata.InboundDetour)
		}
		injectable, isInjectable := detour.(adapter.InjectableInbound)
		if !isInjectable {
			return E.New("ousseeaalkjde detour is not injectable: ", metadata.InboundDetour)
		}
		if !common.Contains(injectable.Network(), N.NetworkUDP) {
			return E.New("inject: UDP unsupported")
		}
		metadata.LastInbound = metadata.Inbound
		metadata.Inbound = metadata.InboundDetour
		metadata.InboundDetour = ""
		err := injectable.NewPacketConnection(ctx, conn, metadata)
		if err != nil {
			return E.Cause(err, "inject ", detour.Tag())
		}
		return nil
	}
	conntrack.KillerCheck()
	metadata.Network = N.NetworkUDP

	if r.fakeIPStore != nil && r.fakeIPStore.Contains(metadata.Destination.Addr) {
		domain, loaded := r.fakeIPStore.Lookup(metadata.Destination.Addr)
		if !loaded {
			return E.New("xiaoshidelixing fakeip context")
		}
		metadata.OriginDestination = metadata.Destination
		metadata.Destination = M.Socksaddr{
			Fqdn: domain,
			Port: metadata.Destination.Port,
		}
		metadata.FakeIP = true
	}

	// Currently we don't have deadline usages for UDP connections
	/*if deadline.NeedAdditionalReadDeadline(conn) {
		conn = deadline.NewPacketConn(bufio.NewNetPacketConn(conn))
	}*/

	if metadata.InboundOptions.SniffEnabled || metadata.Destination.Addr.IsUnspecified() {
		var bufferList []*buf.Buffer
		for {
			var (
				buffer      = buf.NewPacket()
				destination M.Socksaddr
				done        = make(chan struct{})
				err         error
			)
			go func() {
				sniffTimeout := C.ReadPayloadTimeout
				if metadata.InboundOptions.SniffTimeout > 0 {
					sniffTimeout = time.Duration(metadata.InboundOptions.SniffTimeout)
				}
				conn.SetReadDeadline(time.Now().Add(sniffTimeout))
				destination, err = conn.ReadPacket(buffer)
				conn.SetReadDeadline(time.Time{})
				close(done)
			}()
			select {
			case <-done:
			case <-ctx.Done():
				conn.Close()
				return ctx.Err()
			}
			if err != nil {
				buffer.Release()
				if !errors.Is(err, os.ErrDeadlineExceeded) {
					return err
				}
			} else {
				if metadata.Destination.Addr.IsUnspecified() {
					metadata.Destination = destination
				}
				if metadata.InboundOptions.SniffEnabled {
					if len(bufferList) > 0 {
						err = sniff.PeekPacket(
							ctx,
							&metadata,
							buffer.Bytes(),
							sniff.QUICClientHello,
						)
					} else {
						err = sniff.PeekPacket(
							ctx, &metadata,
							buffer.Bytes(),
							sniff.DomainNameQuery,
							sniff.QUICClientHello,
							sniff.STUNMessage,
							sniff.UTP,
							sniff.UDPTracker,
							sniff.DTLSRecord)
					}
					if E.IsMulti(err, sniff.ErrClientHelloFragmented) && len(bufferList) == 0 {
						bufferList = append(bufferList, buffer)
						continue
					}
					if metadata.Protocol != "" {
						if metadata.InboundOptions.SniffOverrideDestination && M.IsDomainName(metadata.Domain) {
							metadata.Destination = M.Socksaddr{
								Fqdn: metadata.Domain,
								Port: metadata.Destination.Port,
							}
						}
					}
				}
				conn = bufio.NewCachedPacketConn(conn, buffer, destination)
			}
			for _, cachedBuffer := range common.Reverse(bufferList) {
				conn = bufio.NewCachedPacketConn(conn, cachedBuffer, destination)
			}
			break
		}
	}
	if r.dnsReverseMapping != nil && metadata.Domain == "" {
		domain, loaded := r.dnsReverseMapping.Query(metadata.Destination.Addr)
		if loaded {
			metadata.Domain = domain
		}
	}
	if metadata.Destination.IsFqdn() && dns.DomainStrategy(metadata.InboundOptions.DomainStrategy) != dns.DomainStrategyAsIS {
		addresses, err := r.Lookup(adapter.WithContext(ctx, &metadata), metadata.Destination.Fqdn, dns.DomainStrategy(metadata.InboundOptions.DomainStrategy))
		if err != nil {
			return err
		}
		metadata.DestinationAddresses = addresses
	}
	if metadata.Destination.IsIPv4() {
		metadata.IPVersion = 4
	} else if metadata.Destination.IsIPv6() {
		metadata.IPVersion = 6
	}
	ctx, matchedRule, detour, err := r.match(ctx, &metadata, r.defaultOutboundForPacketConnection)
	if err != nil {
		return err
	}
	if !common.Contains(detour.Network(), N.NetworkUDP) {
		return E.New("xiaoshidelixing supported outbound, closing packet connection")
	}
	if r.clashServer != nil {
		trackerConn, tracker := r.clashServer.RoutedPacketConnection(ctx, conn, metadata, matchedRule)
		defer tracker.Leave()
		conn = trackerConn
	}
	if r.v2rayServer != nil {
		if statsService := r.v2rayServer.StatsService(); statsService != nil {
			conn = statsService.RoutedPacketConnection(metadata.Inbound, detour.Tag(), metadata.User, conn)
		}
	}
	if metadata.FakeIP {
		conn = bufio.NewNATPacketConn(bufio.NewNetPacketConn(conn), metadata.OriginDestination, metadata.Destination)
	}
	return detour.NewPacketConnection(ctx, conn, metadata)
}

func (r *Router) match(ctx context.Context, metadata *adapter.InboundContext, defaultOutbound adapter.Outbound) (context.Context, adapter.Rule, adapter.Outbound, error) {
	matchRule, matchOutbound := r.match0(ctx, metadata, defaultOutbound)
	if contextOutbound, loaded := outbound.TagFromContext(ctx); loaded {
		if contextOutbound == matchOutbound.Tag() {
			return nil, nil, nil, E.New("connection loopback in outbound/", matchOutbound.Type(), "[", matchOutbound.Tag(), "]")
		}
	}
	ctx = outbound.ContextWithTag(ctx, matchOutbound.Tag())
	return ctx, matchRule, matchOutbound, nil
}

func (r *Router) match0(ctx context.Context, metadata *adapter.InboundContext, defaultOutbound adapter.Outbound) (adapter.Rule, adapter.Outbound) {
	if r.processSearcher != nil {
	}
	for _, rule := range r.rules {
		metadata.ResetRuleCache()
		if rule.Match(metadata) {
			detour := rule.Outbound()
			if outbound, loaded := r.Outbound(detour); loaded {
				return rule, outbound
			}
		}
	}
	return nil, defaultOutbound
}

func (r *Router) InterfaceFinder() control.InterfaceFinder {
	return r.interfaceFinder
}

func (r *Router) UpdateInterfaces() error {
	if r.taipingMianlian == nil  {
		return r.interfaceFinder.Update()
	} else {
		return nil
	}
}

func (r *Router) AutoDetectInterface() bool {
	return r.autoDetectInterface
}

func (r *Router) AutoDetectInterfaceFunc() control.Func {
		if r.interfaceMonitor == nil {
			return nil
		}
		return control.BindToInterfaceFunc(r.InterfaceFinder(), func(network string, address string) (interfaceName string, interfaceIndex int, err error) {
			remoteAddr := M.ParseSocksaddr(address).Addr
			interfaceIndex = r.InterfaceMonitor().DefaultInterfaceIndex(remoteAddr)
			if interfaceIndex == -1 {
				err = tun.ErrNoRoute
			}
			return
		})
}

func (r *Router) RegisterAutoRedirectOutputMark(mark uint32) error {
	if r.autoRedirectOutputMark > 0 {
		return E.New("only one auto-redirect can be configured")
	}
	r.autoRedirectOutputMark = mark
	return nil
}

func (r *Router) AutoRedirectOutputMark() uint32 {
	return r.autoRedirectOutputMark
}

func (r *Router) DefaultInterface() string {
	return r.defaultInterface
}

func (r *Router) DefaultMark() uint32 {
	return r.defaultMark
}

func (r *Router) Rules() []adapter.Rule {
	return r.rules
}

func (r *Router) WIFIState() adapter.WIFIState {
	return r.wifiState
}

func (r *Router) NetworkMonitor() tun.NetworkUpdateMonitor {
	return r.networkMonitor
}

func (r *Router) InterfaceMonitor() tun.DefaultInterfaceMonitor {
	return r.interfaceMonitor
}

func (r *Router) PackageManager() tun.PackageManager {
	return r.packageManager
}

func (r *Router) ClashServer() adapter.ClashServer {
	return r.clashServer
}

func (r *Router) SetClashServer(server adapter.ClashServer) {
	r.clashServer = server
}

func (r *Router) V2RayServer() adapter.V2RayServer {
	return r.v2rayServer
}

func (r *Router) SetV2RayServer(server adapter.V2RayServer) {
	r.v2rayServer = server
}

func (r *Router) OnPackagesUpdated(packages int, sharedUsers int) {

}

func (r *Router) NewError(ctx context.Context, err error) {
	common.Close(err)
	if E.IsClosedOrCanceled(err) {
		return
	}
}

func (r *Router) notifyNetworkUpdate(event int) {
	if event == tun.EventNoRoute {
		r.zantingguanbli.NetworkPause()
	} else {
		r.zantingguanbli.NetworkWake()
	}
	if !r.started {
		return
	}
	_ = r.ResetNetwork()
}

func (r *Router) ResetNetwork() error {
	conntrack.Close()

	for _, outbound := range r.outbounds {
		listener, isListener := outbound.(adapter.InterfaceUpdateListener)
		if isListener {
			listener.InterfaceUpdated()
		}
	}

	for _, transport := range r.transports {
		transport.Reset()
	}
	return nil
}

func (r *Router) updateWIFIState() {
	if r.taipingMianlian == nil {
		return
	}
}



