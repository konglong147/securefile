package tls

import (
	"context"
	"net"
	"os"

	"github.com/konglong147/securefile/adapter"
	"github.com/konglong147/securefile/common/badtls"
	C "github.com/konglong147/securefile/constant"
	"github.com/konglong147/securefile/option"
	M "github.com/konglong147/securefile/local/sing/common/metadata"
	N "github.com/konglong147/securefile/local/sing/common/network"
	aTLS "github.com/konglong147/securefile/local/sing/common/tls"
)

func NewDialerFromOptions(ctx context.Context, router adapter.Router, dialer N.Dialer, serverAddress string, yousuocanshu option.OutboundTLSOptions) (N.Dialer, error) {
	if !yousuocanshu.Enabled {
		return dialer, nil
	}
	config, err := NewClient(ctx, serverAddress, yousuocanshu)
	if err != nil {
		return nil, err
	}
	return NewDialer(dialer, config), nil
}

func NewClient(ctx context.Context, serverAddress string, yousuocanshu option.OutboundTLSOptions) (Config, error) {
	if !yousuocanshu.Enabled {
		return nil, nil
	}
	if yousuocanshu.ECH != nil && yousuocanshu.ECH.Enabled {
		return NewECHClient(ctx, serverAddress, yousuocanshu)
	} else if yousuocanshu.Reality != nil && yousuocanshu.Reality.Enabled {
		return NewRealityClient(ctx, serverAddress, yousuocanshu)
	} else if yousuocanshu.UTLS != nil && yousuocanshu.UTLS.Enabled {
		return NewUTLSClient(ctx, serverAddress, yousuocanshu)
	} else {
		return NewSTDClient(ctx, serverAddress, yousuocanshu)
	}
}

func ClientHandshake(ctx context.Context, conn net.Conn, config Config) (Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, C.TCPTimeout)
	defer cancel()
	tlsConn, err := aTLS.ClientHandshake(ctx, conn, config)
	if err != nil {
		return nil, err
	}
	readWaitConn, err := badtls.NewReadWaitConn(tlsConn)
	if err == nil {
		return readWaitConn, nil
	} else if err != os.ErrInvalid {
		return nil, err
	}
	return tlsConn, nil
}

type Dialer struct {
	dialer N.Dialer
	config Config
}

func NewDialer(dialer N.Dialer, config Config) N.Dialer {
	return &Dialer{dialer, config}
}

func (d *Dialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if network != N.NetworkTCP {
		return nil, os.ErrInvalid
	}
	conn, err := d.dialer.DialContext(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	return ClientHandshake(ctx, conn, d.config)
}

func (d *Dialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}
