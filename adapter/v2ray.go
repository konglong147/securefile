package adapter

import (
	"context"
	"net"

	E "github.com/konglong147/securefile/local/sing/common/exceptions"
	N "github.com/konglong147/securefile/local/sing/common/network"
)

type V2RayServerTransport interface {
	Network() []string
	Serve(listener net.Listener) error
	ServePacket(listener net.PacketConn) error
	Close() error
}

type V2RayServerTransportHandler interface {
	N.TCPConnectionHandler
	E.Handler
}

type V2RayClientTransport interface {
	DialContext(ctx context.Context) (net.Conn, error)
	Close() error
}
