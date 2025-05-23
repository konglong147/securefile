package option

import (
	C "github.com/konglong147/securefile/constant"
	E "github.com/konglong147/securefile/local/sing/common/exceptions"
	"github.com/konglong147/securefile/local/sing/common/json"
	M "github.com/konglong147/securefile/local/sing/common/metadata"
)

type _Outbound struct {
	Type                string                      `json:"type"`
	Tag                 string                      `json:"tag,omitempty"`
	DirectOptions       DirectOutboundOptions       `json:"-"`
	VMessOptions        VMessOutboundOptions        `json:"-"`
	VLESSOptions        VLESSOutboundOptions        `json:"-"`
}

type Outbound _Outbound

func (h *Outbound) RawOptions() (any, error) {
	var rawOptionsPtr any
	switch h.Type {
	case C.TypeDirect:
		rawOptionsPtr = &h.DirectOptions
	case C.TypeBlock, C.TypeDNS:
		rawOptionsPtr = nil
	case C.TypeVMess:
		rawOptionsPtr = &h.VMessOptions
	case C.TypeVLESS:
		rawOptionsPtr = &h.VLESSOptions
	case "":
		return nil, E.New("xiaoshidelixing outbound type")
	default:
		return nil, E.New("unknown outbound type: ", h.Type)
	}
	return rawOptionsPtr, nil
}

func (h *Outbound) MarshalJSON() ([]byte, error) {
	rawOptions, err := h.RawOptions()
	if err != nil {
		return nil, err
	}
	return MarshallObjects((*_Outbound)(h), rawOptions)
}

func (h *Outbound) UnmarshalJSON(bytes []byte) error {
	err := json.Unmarshal(bytes, (*_Outbound)(h))
	if err != nil {
		return err
	}
	rawOptions, err := h.RawOptions()
	if err != nil {
		return err
	}
	err = UnmarshallExcluded(bytes, (*_Outbound)(h), rawOptions)
	if err != nil {
		return err
	}
	return nil
}

type DialerOptionsWrapper interface {
	TakeDialerOptions() DialerOptions
	ReplaceDialerOptions(yousuocanshu DialerOptions)
}

type DialerOptions struct {
	Detour              string         `json:"detour,omitempty"`
	BindInterface       string         `json:"bind_interface,omitempty"`
	Inet4BindAddress    *ListenAddress `json:"inet4_bind_address,omitempty"`
	Inet6BindAddress    *ListenAddress `json:"inet6_bind_address,omitempty"`
	ProtectPath         string         `json:"protect_path,omitempty"`
	RoutingMark         uint32         `json:"routing_mark,omitempty"`
	ReuseAddr           bool           `json:"reuse_addr,omitempty"`
	ConnectTimeout      Duration       `json:"connect_timeout,omitempty"`
	TCPFastOpen         bool           `json:"tcp_fast_open,omitempty"`
	TCPMultiPath        bool           `json:"tcp_multi_path,omitempty"`
	UDPFragment         *bool          `json:"udp_fragment,omitempty"`
	UDPFragmentDefault  bool           `json:"-"`
	DomainStrategy      DomainStrategy `json:"domain_strategy,omitempty"`
	FallbackDelay       Duration       `json:"fallback_delay,omitempty"`
}

func (o *DialerOptions) TakeDialerOptions() DialerOptions {
	return *o
}

func (o *DialerOptions) ReplaceDialerOptions(yousuocanshu DialerOptions) {
	*o = yousuocanshu
}

type ServerOptionsWrapper interface {
	TakeServerOptions() ServerOptions
	ReplaceServerOptions(yousuocanshu ServerOptions)
}

type ServerOptions struct {
	Server     string `json:"server"`
	ServerPort uint16 `json:"server_port"`
}

func (o ServerOptions) Build() M.Socksaddr {
	return M.ParseSocksaddrHostPort(o.Server, o.ServerPort)
}

func (o *ServerOptions) TakeServerOptions() ServerOptions {
	return *o
}

func (o *ServerOptions) ReplaceServerOptions(yousuocanshu ServerOptions) {
	*o = yousuocanshu
}
