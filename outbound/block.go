package outbound

import (
	"context"
	"io"
	"net"

	"github.com/konglong147/securefile/adapter"
	C "github.com/konglong147/securefile/constant"
	M "github.com/konglong147/securefile/local/sing/common/metadata"
	N "github.com/konglong147/securefile/local/sing/common/network"
)

var _ adapter.Outbound = (*Block)(nil)

type Block struct {
	myOutboundAdapter
}

func NewBlock(tag string) *Block {
	return &Block{
		myOutboundAdapter{
			protocol: C.TypeBlock,
			network:  []string{N.NetworkTCP, N.NetworkUDP},
			tag:      tag,
		},
	}
}

func (h *Block) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return nil, io.EOF
}

func (h *Block) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, io.EOF
}

func (h *Block) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	conn.Close()
	return nil
}

func (h *Block) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	conn.Close()
	return nil
}
