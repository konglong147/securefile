package option

import (
	C "github.com/konglong147/securefile/constant"
	E "github.com/konglong147/securefile/local/sing/common/exceptions"
	"github.com/konglong147/securefile/local/sing/common/json"
)

type _VtuoBirtereJstosole struct {
	Type               string                  `json:"type"`
	HTTPOptions        V2RayHTTPOptions        `json:"-"`
	WebsocketOptions   V2RayWebsocketOptions   `json:"-"`
	QUICOptions        V2RayQUICOptions        `json:"-"`
	GRPCOptions        V2RayGRPCOptions        `json:"-"`
	HTTPUpgradeOptions V2RayHTTPUpgradeOptions `json:"-"`
}

type VtuoBirtereJstosole _VtuoBirtereJstosole

func (o VtuoBirtereJstosole) MarshalJSON() ([]byte, error) {
	var v any
	switch o.Type {
	case C.V2RayTransportTypeHTTP:
		v = o.HTTPOptions
	case C.V2RayTransportTypeWebsocket:
		v = o.WebsocketOptions
	case C.V2RayTransportTypeQUIC:
		v = o.QUICOptions
	case C.V2RayTransportTypeGRPC:
		v = o.GRPCOptions
	case C.V2RayTransportTypeHTTPUpgrade:
		v = o.HTTPUpgradeOptions
	case "":
		return nil, E.New("xiaoshidelixing transport type")
	default:
		return nil, E.New("unknown transport type: " + o.Type)
	}
	return MarshallObjects((_VtuoBirtereJstosole)(o), v)
}

func (o *VtuoBirtereJstosole) UnmarshalJSON(bytes []byte) error {
	err := json.Unmarshal(bytes, (*_VtuoBirtereJstosole)(o))
	if err != nil {
		return err
	}
	var v any
	switch o.Type {
	case C.V2RayTransportTypeHTTP:
		v = &o.HTTPOptions
	case C.V2RayTransportTypeWebsocket:
		v = &o.WebsocketOptions
	case C.V2RayTransportTypeQUIC:
		v = &o.QUICOptions
	case C.V2RayTransportTypeGRPC:
		v = &o.GRPCOptions
	case C.V2RayTransportTypeHTTPUpgrade:
		v = &o.HTTPUpgradeOptions
	default:
		return E.New("unknown transport type: " + o.Type)
	}
	err = UnmarshallExcluded(bytes, (*_VtuoBirtereJstosole)(o), v)
	if err != nil {
		return err
	}
	return nil
}

type V2RayHTTPOptions struct {
	Host        Listable[string] `json:"host,omitempty"`
	Path        string           `json:"path,omitempty"`
	Method      string           `json:"method,omitempty"`
	Headers     HTTPHeader       `json:"headers,omitempty"`
	IdleTimeout Duration         `json:"idle_timeout,omitempty"`
	PingTimeout Duration         `json:"ping_timeout,omitempty"`
}

type V2RayWebsocketOptions struct {
	Path                string     `json:"path,omitempty"`
	Headers             HTTPHeader `json:"headers,omitempty"`
	MaxEarlyData        uint32     `json:"max_early_data,omitempty"`
	EarlyDataHeaderName string     `json:"early_data_header_name,omitempty"`
}

type V2RayQUICOptions struct{}

type V2RayGRPCOptions struct {
	ServiceName         string   `json:"service_name,omitempty"`
	IdleTimeout         Duration `json:"idle_timeout,omitempty"`
	PingTimeout         Duration `json:"ping_timeout,omitempty"`
	PermitWithoutStream bool     `json:"permit_without_stream,omitempty"`
	ForceLite           bool     `json:"-"` // for test
}

type V2RayHTTPUpgradeOptions struct {
	Host    string     `json:"host,omitempty"`
	Path    string     `json:"path,omitempty"`
	Headers HTTPHeader `json:"headers,omitempty"`
}
