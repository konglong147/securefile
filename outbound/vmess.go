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

	"github.com/konglong147/securefile/local/sing-vmess"
	"github.com/konglong147/securefile/local/sing-vmess/packetaddr"
	"github.com/konglong147/securefile/local/sing/common"
	E "github.com/konglong147/securefile/local/sing/common/exceptions"
	M "github.com/konglong147/securefile/local/sing/common/metadata"
	N "github.com/konglong147/securefile/local/sing/common/network"
	"github.com/konglong147/securefile/local/sing/common/ntp"
)

var _ adapter.Outbound = (*VMess)(nil)

type VMess struct {
	myOutboundAdapter
	dialer          N.Dialer
	client          *vmess.Client
	serverAddr      M.Socksaddr
	multiplexDialer *mux.Client
	tlsConfig       tls.Config
	transport       adapter.V2RayClientTransport
	packetAddr      bool
	xudp            bool
}

func NewVMess(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, yousuocanshu option.VMessOutboundOptions) (*VMess, error) {
	outboundDialer, err := dialer.New(router, yousuocanshu.DialerOptions)
	if err != nil {
		return nil, err
	}
	outbound := &VMess{
		myOutboundAdapter: myOutboundAdapter{
			protocol:     C.TypeVMess,
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
	
	outbound.multiplexDialer, err = mux.NewClientWithOptions((*vmessDialer)(outbound), logger, common.PtrValueOrDefault(yousuocanshu.Multiplex))
	if err != nil {
		return nil, err
	}
	switch yousuocanshu.PacketEncoding {
	case "":
	case "packetaddr":
		outbound.packetAddr = true
	case "xudp":
		outbound.xudp = true
	default:
		return nil, E.New("unknown packet encoding: ", yousuocanshu.PacketEncoding)
	}
	var clientOptions []vmess.ClientOption
	if timeFunc := ntp.TimeFuncFromContext(ctx); timeFunc != nil {
		clientOptions = append(clientOptions, vmess.ClientWithTimeFunc(timeFunc))
	}
	if yousuocanshu.GlobalPadding {
		clientOptions = append(clientOptions, vmess.ClientWithGlobalPadding())
	}
	if yousuocanshu.AuthenticatedLength {
		clientOptions = append(clientOptions, vmess.ClientWithAuthenticatedLength())
	}
	security := yousuocanshu.Security
	if security == "" {
		security = "auto"
	}
	if security == "auto" && outbound.tlsConfig != nil {
		security = "zero"
	}
	client, err := vmess.NewClient(yousuocanshu.UUID, security, yousuocanshu.AlterId, clientOptions...)
	if err != nil {
		return nil, err
	}
	outbound.client = client
	return outbound, nil
}

func (h *VMess) InterfaceUpdated() {
	if h.transport != nil {
		h.transport.Close()
	}
	if h.multiplexDialer != nil {
		h.multiplexDialer.Reset()
	}
	return
}

func (h *VMess) Close() error {
	return common.Close(common.PtrOrNil(h.multiplexDialer), h.transport)
}

func (h *VMess) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if h.multiplexDialer == nil {
		return (*vmessDialer)(h).DialContext(ctx, network, destination)
	} else {
		return h.multiplexDialer.DialContext(ctx, network, destination)
	}
}

func (h *VMess) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if h.multiplexDialer == nil {
		return (*vmessDialer)(h).ListenPacket(ctx, destination)
	} else {
		return h.multiplexDialer.ListenPacket(ctx, destination)
	}
}

func (h *VMess) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	return NewConnection(ctx, h, conn, metadata)
}

func (h *VMess) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	return NewPacketConnection(ctx, h, conn, metadata)
}

type vmessDialer VMess

func (h *vmessDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
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
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		return h.client.DialEarlyConn(conn, destination), nil
	case N.NetworkUDP:
		return h.client.DialEarlyPacketConn(conn, destination), nil
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (h *vmessDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
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
	if h.packetAddr {
		if destination.IsFqdn() {
			return nil, E.New("packetaddr: domain destination is not supported")
		}
		return packetaddr.NewConn(h.client.DialEarlyPacketConn(conn, M.Socksaddr{Fqdn: packetaddr.SeqPacketMagicAddress}), destination), nil
	} else if h.xudp {
		return h.client.DialEarlyXUDPPacketConn(conn, destination), nil
	} else {
		return h.client.DialEarlyPacketConn(conn, destination), nil
	}
}
