package outbound

import (
	"context"
	"net"
	"os"

	"github.com/konglong147/securefile/adapter"
	"github.com/konglong147/securefile/common/dialer"
	"github.com/konglong147/securefile/common/tls"
	C "github.com/konglong147/securefile/constant"
	"github.com/konglong147/securefile/log"
	"github.com/konglong147/securefile/option"
	"github.com/sagernet/sing/common"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	sHTTP "github.com/sagernet/sing/protocol/http"
)

var _ adapter.Outbound = (*HTTP)(nil)

type HTTP struct {
	myOutboundAdapter
	client *sHTTP.Client
}

func NewHTTP(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.HTTPOutboundOptions) (*HTTP, error) {
	outboundDialer, err := dialer.New(router, options.DialerOptions)
	if err != nil {
		return nil, err
	}
	detour, err := tls.NewDialerFromOptions(ctx, router, outboundDialer, options.Server, common.PtrValueOrDefault(options.TLS))
	if err != nil {
		return nil, err
	}
	return &HTTP{
		myOutboundAdapter{
			protocol:     C.TypeHTTP,
			network:      []string{N.NetworkTCP},
			router:       router,
			logger:       logger,
			tag:          tag,
			dependencies: withDialerDependency(options.DialerOptions),
		},
		sHTTP.NewClient(sHTTP.Options{
			Dialer:   detour,
			Server:   options.ServerOptions.Build(),
			Username: options.Username,
			Password: options.Password,
			Path:     options.Path,
			Headers:  options.Headers.Build(),
		}),
	}, nil
}

func (h *HTTP) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.tag
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "outbound connection to ", destination)
	return h.client.DialContext(ctx, network, destination)
}

func (h *HTTP) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

func (h *HTTP) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	return NewConnection(ctx, h, conn, metadata)
}

func (h *HTTP) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	return os.ErrInvalid
}
