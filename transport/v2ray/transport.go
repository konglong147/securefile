package v2ray

import (
	"context"

	"github.com/konglong147/securefile/adapter"
	"github.com/konglong147/securefile/common/tls"
	C "github.com/konglong147/securefile/constant"
	"github.com/konglong147/securefile/option"
	"github.com/konglong147/securefile/transport/v2rayhttp"
	"github.com/konglong147/securefile/transport/v2rayhttpupgrade"
	"github.com/konglong147/securefile/transport/v2raywebsocket"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type (
	ServerConstructor[O any] func(ctx context.Context, options O, tlsConfig tls.ServerConfig, handler adapter.V2RayServerTransportHandler) (adapter.V2RayServerTransport, error)
	ClientConstructor[O any] func(ctx context.Context, dialer N.Dialer, serverAddr M.Socksaddr, options O, tlsConfig tls.Config) (adapter.V2RayClientTransport, error)
)

func NewServerTransport(ctx context.Context, options option.V2RayTransportOptions, tlsConfig tls.ServerConfig, handler adapter.V2RayServerTransportHandler) (adapter.V2RayServerTransport, error) {
	if options.Type == "" {
		return nil, nil
	}
	switch options.Type {
	case C.V2RayTransportTypeHTTP:
		return v2rayhttp.NewServer(ctx, options.HTTPOptions, tlsConfig, handler)
	case C.V2RayTransportTypeWebsocket:
		return v2raywebsocket.NewServer(ctx, options.WebsocketOptions, tlsConfig, handler)
	case C.V2RayTransportTypeQUIC:
		if tlsConfig == nil {
			return nil, C.ErrTLSRequired
		}
		return NewQUICServer(ctx, options.QUICOptions, tlsConfig, handler)
	case C.V2RayTransportTypeGRPC:
		return NewGRPCServer(ctx, options.GRPCOptions, tlsConfig, handler)
	case C.V2RayTransportTypeHTTPUpgrade:
		return v2rayhttpupgrade.NewServer(ctx, options.HTTPUpgradeOptions, tlsConfig, handler)
	default:
		return nil, E.New("unknown transport type: " + options.Type)
	}
}

func NewClientTransport(ctx context.Context, dialer N.Dialer, serverAddr M.Socksaddr, options option.V2RayTransportOptions, tlsConfig tls.Config) (adapter.V2RayClientTransport, error) {
	if options.Type == "" {
		return nil, nil
	}
	switch options.Type {
	case C.V2RayTransportTypeHTTP:
		return v2rayhttp.NewClient(ctx, dialer, serverAddr, options.HTTPOptions, tlsConfig)
	case C.V2RayTransportTypeGRPC:
		return NewGRPCClient(ctx, dialer, serverAddr, options.GRPCOptions, tlsConfig)
	case C.V2RayTransportTypeWebsocket:
		return v2raywebsocket.NewClient(ctx, dialer, serverAddr, options.WebsocketOptions, tlsConfig)
	case C.V2RayTransportTypeQUIC:
		if tlsConfig == nil {
			return nil, C.ErrTLSRequired
		}
		return NewQUICClient(ctx, dialer, serverAddr, options.QUICOptions, tlsConfig)
	case C.V2RayTransportTypeHTTPUpgrade:
		return v2rayhttpupgrade.NewClient(ctx, dialer, serverAddr, options.HTTPUpgradeOptions, tlsConfig)
	default:
		return nil, E.New("unknown transport type: " + options.Type)
	}
}
