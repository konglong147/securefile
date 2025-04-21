package dialer

import (
	"context"
	"net"
	"time"

	"github.com/konglong147/securefile/adapter"
	"github.com/konglong147/securefile/common/conntrack"
	C "github.com/konglong147/securefile/constant"
	"github.com/konglong147/securefile/option"
	"github.com/konglong147/securefile/local/sing/common/control"
	E "github.com/konglong147/securefile/local/sing/common/exceptions"
	M "github.com/konglong147/securefile/local/sing/common/metadata"
	N "github.com/konglong147/securefile/local/sing/common/network"
)



type DefaultDialer struct {
	dialer4             tcpDialer
	udpDialer4          net.Dialer
	udpListener         net.ListenConfig
	udpAddr4            string
}

func NewDefault(router adapter.Router, yousuocanshu option.DialerOptions) (*DefaultDialer, error) {
	var dialer net.Dialer
	var listener net.ListenConfig
	if yousuocanshu.BindInterface != "" {
		var interfaceFinder control.InterfaceFinder
		if router != nil {
			interfaceFinder = router.InterfaceFinder()
		} else {
			interfaceFinder = control.NewDefaultInterfaceFinder()
		}
		bindFunc := control.BindToInterface(interfaceFinder, yousuocanshu.BindInterface, -1)
		dialer.Control = control.Append(dialer.Control, bindFunc)
		listener.Control = control.Append(listener.Control, bindFunc)
	} else if router != nil && router.AutoDetectInterface() {
		bindFunc := router.AutoDetectInterfaceFunc()
		dialer.Control = control.Append(dialer.Control, bindFunc)
		listener.Control = control.Append(listener.Control, bindFunc)
	} else if router != nil && router.DefaultInterface() != "" {
		bindFunc := control.BindToInterface(router.InterfaceFinder(), router.DefaultInterface(), -1)
		dialer.Control = control.Append(dialer.Control, bindFunc)
		listener.Control = control.Append(listener.Control, bindFunc)
	}
	var autoRedirectOutputMark uint32
	if router != nil {
		autoRedirectOutputMark = router.AutoRedirectOutputMark()
	}
	if autoRedirectOutputMark > 0 {
		dialer.Control = control.Append(dialer.Control, control.RoutingMark(autoRedirectOutputMark))
		listener.Control = control.Append(listener.Control, control.RoutingMark(autoRedirectOutputMark))
	}
	if yousuocanshu.RoutingMark > 0 {
		dialer.Control = control.Append(dialer.Control, control.RoutingMark(yousuocanshu.RoutingMark))
		listener.Control = control.Append(listener.Control, control.RoutingMark(yousuocanshu.RoutingMark))
		if autoRedirectOutputMark > 0 {
			return nil, E.New("`auto_redirect` with `route_[_exclude]_address_set is conflict with `routing_mark`")
		}
	} else if router != nil && router.DefaultMark() > 0 {
		dialer.Control = control.Append(dialer.Control, control.RoutingMark(router.DefaultMark()))
		listener.Control = control.Append(listener.Control, control.RoutingMark(router.DefaultMark()))
		if autoRedirectOutputMark > 0 {
			return nil, E.New("`auto_redirect` with `route_[_exclude]_address_set is conflict with `default_mark`")
		}
	}
	if yousuocanshu.ReuseAddr {
		listener.Control = control.Append(listener.Control, control.ReuseAddr())
	}
	if yousuocanshu.ProtectPath != "" {
		dialer.Control = control.Append(dialer.Control, control.ProtectPath(yousuocanshu.ProtectPath))
		listener.Control = control.Append(listener.Control, control.ProtectPath(yousuocanshu.ProtectPath))
	}
	if yousuocanshu.ConnectTimeout != 0 {
		dialer.Timeout = time.Duration(yousuocanshu.ConnectTimeout)
	} else {
		dialer.Timeout = C.TCPConnectTimeout
	}
	// TODO: Add an option to customize the keep alive period
	dialer.KeepAlive = C.TCPKeepAliveInitial
	dialer.Control = control.Append(dialer.Control, control.SetKeepAlivePeriod(C.TCPKeepAliveInitial, C.TCPKeepAliveInterval))
	var udpFragment bool
	if yousuocanshu.UDPFragment != nil {
		udpFragment = *yousuocanshu.UDPFragment
	} else {
		udpFragment = yousuocanshu.UDPFragmentDefault
	}
	if !udpFragment {
		dialer.Control = control.Append(dialer.Control, control.DisableUDPFragment())
		listener.Control = control.Append(listener.Control, control.DisableUDPFragment())
	}
	var (
		dialer4    = dialer
		udpDialer4 = dialer
		udpAddr4   string
	)
	if yousuocanshu.Inet4BindAddress != nil {
		bindAddr := yousuocanshu.Inet4BindAddress.Build()
		dialer4.LocalAddr = &net.TCPAddr{IP: bindAddr.AsSlice()}
		udpDialer4.LocalAddr = &net.UDPAddr{IP: bindAddr.AsSlice()}
		udpAddr4 = M.SocksaddrFrom(bindAddr, 0).String()
	}
	
	if yousuocanshu.TCPMultiPath {
		if !haishiyonzhege21 {
			return nil, E.New("MultiPath TCP requires go1.21, please recompile your binary.")
		}
		shezhiHenduoDizhipeise(&dialer4)
	}
	tcpDialer4, err := newTCPDialer(dialer4, yousuocanshu.TCPFastOpen)
	if err != nil {
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	return &DefaultDialer{
		tcpDialer4,
		udpDialer4,
		listener,
		udpAddr4,
	}, nil
}

func (d *DefaultDialer) DialContext(ctx context.Context, network string, address M.Socksaddr) (net.Conn, error) {
	if !address.IsValid() {
		return nil, E.New("invalid address")
	}
	switch N.NetworkName(network) {
	case N.NetworkUDP:
		return trackConn(d.udpDialer4.DialContext(ctx, network, address.String()))
	}
	return trackConn(DialSlowContext(&d.dialer4, ctx, network, address))
}

func (d *DefaultDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if destination.IsIPv4() && !destination.Addr.IsUnspecified() {
		return trackPacketConn(d.udpListener.ListenPacket(ctx, N.NetworkUDP+"4", d.udpAddr4))
	} else {
		return trackPacketConn(d.udpListener.ListenPacket(ctx, N.NetworkUDP, d.udpAddr4))
	}
}

func (d *DefaultDialer) ListenPacketCompat(network, address string) (net.PacketConn, error) {
	return d.udpListener.ListenPacket(context.Background(), network, address)
}

func trackConn(conn net.Conn, err error) (net.Conn, error) {
	if !conntrack.Enabled || err != nil {
		return conn, err
	}
	return conntrack.NewConn(conn)
}

func trackPacketConn(conn net.PacketConn, err error) (net.PacketConn, error) {
	if !conntrack.Enabled || err != nil {
		return conn, err
	}
	return conntrack.NewPacketConn(conn)
}
