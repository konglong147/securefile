package deadline

import (
	"net"
	"time"

	"github.com/konglong147/securefile/local/sing/common/buf"
	M "github.com/konglong147/securefile/local/sing/common/metadata"
	N "github.com/konglong147/securefile/local/sing/common/network"
)

type PacketConn struct {
	N.NetPacketConn
	reader PacketReader
}

func NewPacketConn(conn N.NetPacketConn) N.NetPacketConn {
	if deadlineConn, isDeadline := conn.(*PacketConn); isDeadline {
		return deadlineConn
	}
	return NewSerialPacketConn(&PacketConn{NetPacketConn: conn, reader: NewPacketReader(conn)})
}

func NewFallbackPacketConn(conn N.NetPacketConn) N.NetPacketConn {
	if deadlineConn, isDeadline := conn.(*PacketConn); isDeadline {
		return deadlineConn
	}
	return NewSerialPacketConn(&PacketConn{NetPacketConn: conn, reader: NewFallbackPacketReader(conn)})
}

func (c *PacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	return c.reader.ReadFrom(p)
}

func (c *PacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	return c.reader.ReadPacket(buffer)
}

func (c *PacketConn) SetReadDeadline(t time.Time) error {
	return c.reader.SetReadDeadline(t)
}

func (c *PacketConn) ReaderReplaceable() bool {
	return c.reader.ReaderReplaceable()
}

func (c *PacketConn) WriterReplaceable() bool {
	return true
}

func (c *PacketConn) Upstream() any {
	return c.NetPacketConn
}

func (c *PacketConn) NeedAdditionalReadDeadline() bool {
	return false
}
