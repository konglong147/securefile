package outbound

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"

	"github.com/konglong147/securefile/adapter"
	"github.com/konglong147/securefile/log"
	"github.com/konglong147/securefile/local/sing/common"
	"github.com/konglong147/securefile/local/sing/common/auth"
	E "github.com/konglong147/securefile/local/sing/common/exceptions"
	M "github.com/konglong147/securefile/local/sing/common/metadata"
	N "github.com/konglong147/securefile/local/sing/common/network"
	"github.com/konglong147/securefile/local/sing/protocol/socks"
)

type ProxyListener struct {
	ctx           context.Context
	dialer        N.Dialer
	tcpListener   *net.TCPListener
	username      string
	password      string
	authenticator *auth.Authenticator
}

func NewProxyListener(ctx context.Context, dialer N.Dialer) *ProxyListener {
	var usernameB [64]byte
	var passwordB [64]byte
	rand.Read(usernameB[:])
	rand.Read(passwordB[:])
	username := hex.EncodeToString(usernameB[:])
	password := hex.EncodeToString(passwordB[:])
	return &ProxyListener{
		ctx:           ctx,
		dialer:        dialer,
		authenticator: auth.NewAuthenticator([]auth.User{{Username: username, Password: password}}),
		username:      username,
		password:      password,
	}
}

func (l *ProxyListener) Start() error {
	tcpListener, err := net.ListenTCP("tcp", &net.TCPAddr{
		IP: net.IPv4(127, 0, 0, 1),
	})
	if err != nil {
		return err
	}
	l.tcpListener = tcpListener
	go l.acceptLoop()
	return nil
}

func (l *ProxyListener) Port() uint16 {
	if l.tcpListener == nil {
		panic("start listener first")
	}
	return M.SocksaddrFromNet(l.tcpListener.Addr()).Port
}

func (l *ProxyListener) Username() string {
	return l.username
}

func (l *ProxyListener) Password() string {
	return l.password
}

func (l *ProxyListener) Close() error {
	return common.Close(l.tcpListener)
}

func (l *ProxyListener) acceptLoop() {
	for {
		tcpConn, err := l.tcpListener.AcceptTCP()
		if err != nil {
			return
		}
		ctx := log.ContextWithNewID(l.ctx)
		go func() {
			hErr := l.accept(ctx, tcpConn)
			if hErr != nil {
				if E.IsClosedOrCanceled(hErr) {
					return
				}
			}
		}()
	}
}

func (l *ProxyListener) accept(ctx context.Context, conn *net.TCPConn) error {
	return socks.HandleConnection(ctx, conn, l.authenticator, l, M.Metadata{})
}

func (l *ProxyListener) NewConnection(ctx context.Context, conn net.Conn, upstreamMetadata M.Metadata) error {
	var metadata adapter.InboundContext
	metadata.Network = N.NetworkTCP
	metadata.Destination = upstreamMetadata.Destination
	return NewConnection(ctx, l.dialer, conn, metadata)
}

func (l *ProxyListener) NewPacketConnection(ctx context.Context, conn N.PacketConn, upstreamMetadata M.Metadata) error {
	var metadata adapter.InboundContext
	metadata.Network = N.NetworkUDP
	metadata.Destination = upstreamMetadata.Destination
	return NewPacketConnection(ctx, l.dialer, conn, metadata)
}
