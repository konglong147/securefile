package adapter

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"sync"

	"github.com/konglong147/securefile/common/geoip"
	C "github.com/konglong147/securefile/constant"
	"github.com/konglong147/securefile/local/sing-dns"
	"github.com/konglong147/securefile/local/sing-tun"
	"github.com/konglong147/securefile/local/sing/common/control"
	M "github.com/konglong147/securefile/local/sing/common/metadata"
	N "github.com/konglong147/securefile/local/sing/common/network"
	"github.com/konglong147/securefile/local/sing/common/x/list"
	"github.com/konglong147/securefile/local/sing/service"

	mdns "github.com/miekg/dns"
	"go4.org/netipx"
)

type Router interface {
	Service
	PreStarter
	PostStarter
	Cleanup() error

	Outbounds() []Outbound
	Outbound(tag string) (Outbound, bool)
	DefaultOutbound(network string) (Outbound, error)


	ConnectionRouter

	GeoIPReader() *geoip.Reader
	LoadGeosite(code string) (Rule, error)

	RuleSet(tag string) (RuleSet, bool)


	Exchange(ctx context.Context, message *mdns.Msg) (*mdns.Msg, error)
	Lookup(ctx context.Context, domain string, strategy dns.DomainStrategy) ([]netip.Addr, error)
	LookupDefault(ctx context.Context, domain string) ([]netip.Addr, error)

	InterfaceFinder() control.InterfaceFinder
	UpdateInterfaces() error
	DefaultInterface() string
	AutoDetectInterface() bool
	AutoDetectInterfaceFunc() control.Func
	DefaultMark() uint32
	RegisterAutoRedirectOutputMark(mark uint32) error
	AutoRedirectOutputMark() uint32
	NetworkMonitor() tun.NetworkUpdateMonitor
	InterfaceMonitor() tun.DefaultInterfaceMonitor
	PackageManager() tun.PackageManager
	WIFIState() WIFIState
	Rules() []Rule

	ClashServer() ClashServer
	SetClashServer(server ClashServer)

	V2RayServer() V2RayServer
	SetV2RayServer(server V2RayServer)

	ResetNetwork() error
}

func ContextWithRouter(ctx context.Context, router Router) context.Context {
	return service.ContextWith(ctx, router)
}

func RouterFromContext(ctx context.Context) Router {
	return service.FromContext[Router](ctx)
}

type HeadlessRule interface {
	Match(metadata *InboundContext) bool
	String() string
}

type Rule interface {
	HeadlessRule
	Service
	Type() string
	UpdateGeosite() error
	Outbound() string
}

type DNSRule interface {
	Rule
	DisableCache() bool
	RewriteTTL() *uint32
	ClientSubnet() *netip.Prefix
	WithAddressLimit() bool
	MatchAddressLimit(metadata *InboundContext) bool
}

type RuleSet interface {
	Name() string
	StartContext(ctx context.Context, startContext *HTTPStartContext) error
	PostStart() error
	Metadata() RuleSetMetadata
	ExtractIPSet() []*netipx.IPSet
	IncRef()
	DecRef()
	Cleanup()
	RegisterCallback(callback RuleSetUpdateCallback) *list.Element[RuleSetUpdateCallback]
	UnregisterCallback(element *list.Element[RuleSetUpdateCallback])
	Close() error
	HeadlessRule
}

type RuleSetUpdateCallback func(it RuleSet)

type RuleSetMetadata struct {
	ContainsProcessRule bool
	ContainsWIFIRule    bool
	ContainsIPCIDRRule  bool
}
type HTTPStartContext struct {
	access          sync.Mutex
	httpClientCache map[string]*http.Client
}

func NewHTTPStartContext() *HTTPStartContext {
	return &HTTPStartContext{
		httpClientCache: make(map[string]*http.Client),
	}
}

func (c *HTTPStartContext) HTTPClient(detour string, dialer N.Dialer) *http.Client {
	c.access.Lock()
	defer c.access.Unlock()
	if httpClient, loaded := c.httpClientCache[detour]; loaded {
		return httpClient
	}
	httpClient := &http.Client{
		Transport: &http.Transport{
			ForceAttemptHTTP2:   true,
			TLSHandshakeTimeout: C.TCPTimeout,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, M.ParseSocksaddr(addr))
			},
		},
	}
	c.httpClientCache[detour] = httpClient
	return httpClient
}

func (c *HTTPStartContext) Close() {
	c.access.Lock()
	defer c.access.Unlock()
	for _, client := range c.httpClientCache {
		client.CloseIdleConnections()
	}
}

type InterfaceUpdateListener interface {
	InterfaceUpdated()
}

type WIFIState struct {
	SSID  string
	BSSID string
}
