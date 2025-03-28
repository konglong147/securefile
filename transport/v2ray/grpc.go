//go:build with_grpc

package v2ray

import (
	"context"

	"github.com/konglong147/securefile/adapter"
	"github.com/konglong147/securefile/common/tls"
	"github.com/konglong147/securefile/option"
	"github.com/konglong147/securefile/transport/v2raygrpc"
	"github.com/konglong147/securefile/transport/v2raygrpclite"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func NewGRPCServer(ctx context.Context, options option.V2RayGRPCOptions, tlsConfig tls.ServerConfig, handler adapter.V2RayServerTransportHandler) (adapter.V2RayServerTransport, error) {
	if options.ForceLite {
		return v2raygrpclite.NewServer(ctx, options, tlsConfig, handler)
	}
	return v2raygrpc.NewServer(ctx, options, tlsConfig, handler)
}

func NewGRPCClient(ctx context.Context, dialer N.Dialer, serverAddr M.Socksaddr, options option.V2RayGRPCOptions, tlsConfig tls.Config) (adapter.V2RayClientTransport, error) {
	if options.ForceLite {
		return v2raygrpclite.NewClient(ctx, dialer, serverAddr, options, tlsConfig), nil
	}
	return v2raygrpc.NewClient(ctx, dialer, serverAddr, options, tlsConfig)
}
