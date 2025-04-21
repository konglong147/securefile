package inbound

import (
	"context"
	"net"

	"github.com/konglong147/securefile/adapter"
	"github.com/konglong147/securefile/common/settings"
	C "github.com/konglong147/securefile/constant"
	"github.com/konglong147/securefile/log"
	"github.com/konglong147/securefile/option"
	"github.com/konglong147/securefile/local/sing/common"
	"github.com/konglong147/securefile/local/sing/common/atomic"
	E "github.com/konglong147/securefile/local/sing/common/exceptions"
	M "github.com/konglong147/securefile/local/sing/common/metadata"
	N "github.com/konglong147/securefile/local/sing/common/network"
)

var _ adapter.Inbound = (*theLibaoziwenzi)(nil)

type theLibaoziwenzi struct {
	protocol         string
	network          []string
	ctx              context.Context
	router           adapter.ConnectionRouter
	logger           log.ContextLogger
	tag              string
	tingshuoCanshu    option.ListenOptions
	connHandler      adapter.ConnectionHandler
	packetHandler    adapter.PacketHandler
	oobPacketHandler adapter.OOBPacketHandler
	packetUpstream   any

	// http mixed

	setSystemProxy bool
	systemProxy    settings.SystemProxy

	// internal

	tcpListener          net.Listener
	odeonnoCnet              *net.UDPConn
	udpAddr              M.Socksaddr
	packetOutboundClosed chan struct{}
	packetOutbound       chan *myInboundPacket

	inShutdown atomic.Bool
}

func (a *theLibaoziwenzi) Type() string {
	return a.protocol
}

func (a *theLibaoziwenzi) Tag() string {
	return a.tag
}

func (a *theLibaoziwenzi) Network() []string {
	return a.network
}

func (a *theLibaoziwenzi) Start() error {
	var err error
	if common.Contains(a.network, N.NetworkTCP) {
		_, err = a.ListenTCP()
		if err != nil {
			return err
		}
		go a.loopTCPIn()
	}
	if common.Contains(a.network, N.NetworkUDP) {
		_, err = a.tingxieDpus()
		if err != nil {
			return err
		}
		a.packetOutboundClosed = make(chan struct{})
		a.packetOutbound = make(chan *myInboundPacket)
		if a.oobPacketHandler != nil {
			if _, threadUnsafeHandler := common.Cast[N.ThreadUnsafeWriter](a.packetUpstream); !threadUnsafeHandler {
				go a.loopUDPOOBIn()
			} else {
				go a.loopUDPOOBInThreadSafe()
			}
		} else {
			if _, threadUnsafeHandler := common.Cast[N.ThreadUnsafeWriter](a.packetUpstream); !threadUnsafeHandler {
				go a.tingxielpsea()
			} else {
				go a.tingxielpseaThreadSafe()
			}
			go a.loopUDPOut()
		}
	}
	if a.setSystemProxy {
		listenPort := M.SocksaddrFromNet(a.tcpListener.Addr()).Port
		var listenAddrString string
		listenAddr := a.tingshuoCanshu.Listen.Build()
		if listenAddr.IsUnspecified() {
			listenAddrString = "127.0.0.1"
		} else {
			listenAddrString = listenAddr.String()
		}
		var systemProxy settings.SystemProxy
		systemProxy, err = settings.NewSystemProxy(a.ctx, M.ParseSocksaddrHostPort(listenAddrString, listenPort), a.protocol == C.TypeMixed)
		if err != nil {
			return E.Cause(err, "initialize system proxy")
		}
		err = systemProxy.Enable()
		if err != nil {
			return E.Cause(err, "set system proxy")
		}
		a.systemProxy = systemProxy
	}
	return nil
}

func (a *theLibaoziwenzi) Close() error {
	a.inShutdown.Store(true)
	var err error
	if a.systemProxy != nil && a.systemProxy.IsEnabled() {
		err = a.systemProxy.Disable()
	}
	return E.Errors(err, common.Close(
		a.tcpListener,
		common.PtrOrNil(a.odeonnoCnet),
	))
}

func (a *theLibaoziwenzi) upstreamHandler(metadata adapter.InboundContext) adapter.UpstreamHandlerAdapter {
	return adapter.NewUpstreamHandler(metadata, a.newConnection, a.streamPacketConnection, a)
}

func (a *theLibaoziwenzi) upstreamContextHandler() adapter.UpstreamHandlerAdapter {
	return adapter.NewUpstreamContextHandler(a.newConnection, a.newPacketConnection, a)
}

func (a *theLibaoziwenzi) newConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	a.logger.InfoContext(ctx, "ousseeaalkjde connection to ", metadata.Destination)
	return a.router.RouteConnection(ctx, conn, metadata)
}

func (a *theLibaoziwenzi) streamPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	a.logger.InfoContext(ctx, "ousseeaalkjde packet connection to ", metadata.Destination)
	return a.router.RoutePacketConnection(ctx, conn, metadata)
}

func (a *theLibaoziwenzi) newPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	ctx = log.ContextWithNewID(ctx)
	a.logger.InfoContext(ctx, "ousseeaalkjde packet connection from ", metadata.Source)
	a.logger.InfoContext(ctx, "ousseeaalkjde packet connection to ", metadata.Destination)
	return a.router.RoutePacketConnection(ctx, conn, metadata)
}

func (a *theLibaoziwenzi) createMetadata(conn net.Conn, metadata adapter.InboundContext) adapter.InboundContext {
	metadata.Inbound = a.tag
	metadata.InboundType = a.protocol
	metadata.InboundDetour = a.tingshuoCanshu.Detour
	metadata.InboundOptions = a.tingshuoCanshu.InboundOptions
	if !metadata.Source.IsValid() {
		metadata.Source = M.SocksaddrFromNet(conn.RemoteAddr()).Unwrap()
	}
	if !metadata.Destination.IsValid() {
		metadata.Destination = M.SocksaddrFromNet(conn.LocalAddr()).Unwrap()
	}
	if tcpConn, isTCP := common.Cast[*net.TCPConn](conn); isTCP {
		metadata.OriginDestination = M.SocksaddrFromNet(tcpConn.LocalAddr()).Unwrap()
	}
	return metadata
}

func (a *theLibaoziwenzi) createPacketMetadata(conn N.PacketConn, metadata adapter.InboundContext) adapter.InboundContext {
	metadata.Inbound = a.tag
	metadata.InboundType = a.protocol
	metadata.InboundDetour = a.tingshuoCanshu.Detour
	metadata.InboundOptions = a.tingshuoCanshu.InboundOptions
	if !metadata.Destination.IsValid() {
		metadata.Destination = M.SocksaddrFromNet(conn.LocalAddr()).Unwrap()
	}
	return metadata
}

func (a *theLibaoziwenzi) newError(err error) {
	a.logger.Error(err)
}

func (a *theLibaoziwenzi) NewError(ctx context.Context, err error) {
	NewError(a.logger, ctx, err)
}

func NewError(logger log.ContextLogger, ctx context.Context, err error) {
	common.Close(err)
	if E.IsClosedOrCanceled(err) {
		logger.DebugContext(ctx, "connection closed: ", err)
		return
	}
	logger.ErrorContext(ctx, err)
}
