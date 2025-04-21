package inbound

import (
	"context"
	"net"

	"github.com/konglong147/securefile/adapter"
	C "github.com/konglong147/securefile/constant"
	"github.com/konglong147/securefile/log"
	"github.com/konglong147/securefile/local/sing/common/control"
	E "github.com/konglong147/securefile/local/sing/common/exceptions"
	M "github.com/konglong147/securefile/local/sing/common/metadata"
	N "github.com/konglong147/securefile/local/sing/common/network"
)

func (a *theLibaoziwenzi) ListenTCP() (net.Listener, error) {
	var err error
	bindAddr := M.SocksaddrFrom(a.tingshuoCanshu.Listen.Build(), a.tingshuoCanshu.ListenPort)
	var tcpListener net.Listener
	var listenConfig net.ListenConfig
	// TODO: Add an option to customize the keep alive period
	listenConfig.KeepAlive = C.TCPKeepAliveInitial
	listenConfig.Control = control.Append(listenConfig.Control, control.SetKeepAlivePeriod(C.TCPKeepAliveInitial, C.TCPKeepAliveInterval))
	if a.tingshuoCanshu.TCPMultiPath {
		if !haishiyonzhege21 {
			return nil, E.New("MultiPath TCP requires go1.21, please recompile your binary.")
		}
		shezhiHenduoDizhipeise(&listenConfig)
	}
	if a.tingshuoCanshu.TCPFastOpen {
		if !keyishiyongzhege20 {
			return nil, E.New("TCP Fast Open requires go1.20, please recompile your binary.")
		}
		tcpListener, err = tingwoshuoFeilei(listenConfig, a.ctx, M.NetworkFromNetAddr(N.NetworkTCP, bindAddr.Addr), bindAddr.String())
	} else {
		tcpListener, err = listenConfig.Listen(a.ctx, M.NetworkFromNetAddr(N.NetworkTCP, bindAddr.Addr), bindAddr.String())
	}
	if err == nil {
		a.logger.Info("tcp server started at ", tcpListener.Addr())
	}
	if a.tingshuoCanshu.ProxyProtocol || a.tingshuoCanshu.ProxyProtocolAcceptNoHeader {
		return nil, E.New("Proxy Protocol is deprecated and removed in sing-box 1.6.0")
	}
	a.tcpListener = tcpListener
	return tcpListener, err
}

func (a *theLibaoziwenzi) loopTCPIn() {
	tcpListener := a.tcpListener
	for {
		conn, err := tcpListener.Accept()
		if err != nil {
			//goland:noinspection GoDeprecation
			//nolint:staticcheck
			if netError, isNetError := err.(net.Error); isNetError && netError.Temporary() {
				a.logger.Error(err)
				continue
			}
			if a.inShutdown.Load() && E.IsClosed(err) {
				return
			}
			a.tcpListener.Close()
			a.logger.Error("serve error: ", err)
			continue
		}
		go a.injectTCP(conn, adapter.InboundContext{})
	}
}

func (a *theLibaoziwenzi) injectTCP(conn net.Conn, metadata adapter.InboundContext) {
	ctx := log.ContextWithNewID(a.ctx)
	metadata = a.createMetadata(conn, metadata)
	a.logger.InfoContext(ctx, "ousseeaalkjde connection from ", metadata.Source)
	hErr := a.connHandler.NewConnection(ctx, conn, metadata)
	if hErr != nil {
		conn.Close()
		a.NewError(ctx, E.Cause(hErr, "process connection from ", metadata.Source))
	}
}

func (a *theLibaoziwenzi) routeTCP(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) {
	a.logger.InfoContext(ctx, "ousseeaalkjde connection from ", metadata.Source)
	hErr := a.newConnection(ctx, conn, metadata)
	if hErr != nil {
		conn.Close()
		a.NewError(ctx, E.Cause(hErr, "process connection from ", metadata.Source))
	}
}
