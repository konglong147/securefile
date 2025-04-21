package outbound

import (
	"context"
	"net"

	"github.com/konglong147/securefile/adapter"
	"github.com/konglong147/securefile/common/dialer"
	"github.com/konglong147/securefile/common/mux"
	"github.com/konglong147/securefile/common/tls"
	C "github.com/konglong147/securefile/constant"
	"github.com/konglong147/securefile/log"
	"github.com/konglong147/securefile/option"
	"github.com/konglong147/securefile/local/sing-vmess/packetaddr"
	"github.com/konglong147/securefile/local/sing-vmess/vless"
	"github.com/konglong147/securefile/local/sing/common"
	"github.com/konglong147/securefile/local/sing/common/bufio"
	E "github.com/konglong147/securefile/local/sing/common/exceptions"
	M "github.com/konglong147/securefile/local/sing/common/metadata"
	N "github.com/konglong147/securefile/local/sing/common/network"
)

var _ adapter.Outbound = (*VLESS)(nil)

type VLESS struct {
	myOutboundAdapter
	dialer          N.Dialer
	client          *vless.Client
	serverAddr      M.Socksaddr
	multiplexDialer *mux.Client
	tlsConfig       tls.Config
	transport       adapter.V2RayClientTransport
	packetAddr      bool
	xudp            bool
}

func NewVLESS(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, yousuocanshu option.VLESSOutboundOptions) (*VLESS, error) {
	outboundDialer, err := dialer.New(router, yousuocanshu.DialerOptions)
	if err != nil {
		return nil, err
	}
	outbound := &VLESS{
		myOutboundAdapter: myOutboundAdapter{
			protocol:     C.TypeVLESS,
			network:      yousuocanshu.Network.Build(),
			router:       router,
			tag:          tag,
			dependencies: withDialerDependency(yousuocanshu.DialerOptions),
		},
		dialer:     outboundDialer,
		serverAddr: yousuocanshu.ServerOptions.Build(),
	}
	if yousuocanshu.TLS != nil {
		outbound.tlsConfig, err = tls.NewClient(ctx, yousuocanshu.Server, common.PtrValueOrDefault(yousuocanshu.TLS))
		if err != nil {
			return nil, err
		}
	}
	if yousuocanshu.PacketEncoding == nil {
		outbound.xudp = true
	} else {
		switch *yousuocanshu.PacketEncoding {
		case "":
		case "packetaddr":
			outbound.packetAddr = true
		case "xudp":
			outbound.xudp = true
		default:
			return nil, E.New("unknown packet encoding: ", yousuocanshu.PacketEncoding)
		}
	}
	outbound.client, err = vless.NewClient(yousuocanshu.UUID, yousuocanshu.Flow, logger)
	if err != nil {
		return nil, err
	}
	outbound.multiplexDialer, err = mux.NewClientWithOptions((*vlessDialer)(outbound), logger, common.PtrValueOrDefault(yousuocanshu.Multiplex))
	if err != nil {
		return nil, err
	}
	return outbound, nil
}

func (h *VLESS) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if h.multiplexDialer == nil {
		return (*vlessDialer)(h).DialContext(ctx, network, destination)
	} else {
		return h.multiplexDialer.DialContext(ctx, network, destination)
	}
}

func (h *VLESS) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if h.multiplexDialer == nil {
		return (*vlessDialer)(h).ListenPacket(ctx, destination)
	} else {
		return h.multiplexDialer.ListenPacket(ctx, destination)
	}
}

func (h *VLESS) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	return NewConnection(ctx, h, conn, metadata)
}

func (h *VLESS) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	return NewPacketConnection(ctx, h, conn, metadata)
}

func (h *VLESS) InterfaceUpdated() {
	if h.transport != nil {
		h.transport.Close()
	}
	if h.multiplexDialer != nil {
		h.multiplexDialer.Reset()
	}
	return
}

func (h *VLESS) Close() error {
	return common.Close(common.PtrOrNil(h.multiplexDialer), h.transport)
}

type vlessDialer VLESS

func (h *vlessDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.tag
	metadata.Destination = destination
	var conn net.Conn
	var err error
	if h.transport != nil {
		conn, err = h.transport.DialContext(ctx)
	} else {
		conn, err = h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
		if err == nil && h.tlsConfig != nil {
			conn, err = tls.ClientHandshake(ctx, conn, h.tlsConfig)
		}
	}
	if err != nil {
		return nil, err
	}
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		return h.client.DialEarlyConn(conn, destination)
	case N.NetworkUDP:
		if h.xudp {
			return h.client.DialEarlyXUDPPacketConn(conn, destination)
		} else if h.packetAddr {
			if destination.IsFqdn() {
				return nil, E.New("packetaddr: domain destination is not supported")
			}
			packetConn, err := h.client.DialEarlyPacketConn(conn, M.Socksaddr{Fqdn: packetaddr.SeqPacketMagicAddress})
			if err != nil {
				return nil, err
			}
			return bufio.NewBindPacketConn(packetaddr.NewConn(packetConn, destination), destination), nil
		} else {
			return h.client.DialEarlyPacketConn(conn, destination)
		}
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (h *vlessDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.tag
	metadata.Destination = destination
	var conn net.Conn
	var err error
	if h.transport != nil {
		conn, err = h.transport.DialContext(ctx)
	} else {
		conn, err = h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
		if err == nil && h.tlsConfig != nil {
			conn, err = tls.ClientHandshake(ctx, conn, h.tlsConfig)
		}
	}
	if err != nil {
		common.Close(conn)
		return nil, err
	}
	if h.xudp {
		return h.client.DialEarlyXUDPPacketConn(conn, destination)
	} else if h.packetAddr {
		if destination.IsFqdn() {
			return nil, E.New("packetaddr: domain destination is not supported")
		}
		conn, err := h.client.DialEarlyPacketConn(conn, M.Socksaddr{Fqdn: packetaddr.SeqPacketMagicAddress})
		if err != nil {
			return nil, err
		}
		return packetaddr.NewConn(conn, destination), nil
	} else {
		return h.client.DialEarlyPacketConn(conn, destination)
	}
}
