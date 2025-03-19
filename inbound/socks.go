package inbound

import (
	"context"
	"net"
	"os"

	"github.com/konglong147/securefile/adapter"
	"github.com/konglong147/securefile/common/uot"
	C "github.com/konglong147/securefile/constant"
	"github.com/konglong147/securefile/log"
	"github.com/konglong147/securefile/option"
	"github.com/sagernet/sing/common/auth"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

var (
	_ adapter.Inbound           = (*Socks)(nil)
	_ adapter.InjectableInbound = (*Socks)(nil)
)

type Socks struct {
	myInboundAdapter
	authenticator *auth.Authenticator
}

func NewSocks(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SocksInboundOptions) *Socks {
	inbound := &Socks{
		myInboundAdapter{
			protocol:      C.TypeSOCKS,
			network:       []string{N.NetworkTCP},
			ctx:           ctx,
			router:        uot.NewRouter(router, logger),
			logger:        logger,
			tag:           tag,
			listenOptions: options.ListenOptions,
		},
		auth.NewAuthenticator(options.Users),
	}
	inbound.connHandler = inbound
	return inbound
}

func (h *Socks) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	return socks.HandleConnection(ctx, conn, h.authenticator, h.upstreamUserHandler(metadata), adapter.UpstreamMetadata(metadata))
}

func (h *Socks) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	return os.ErrInvalid
}
