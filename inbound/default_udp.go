package inbound

import (
	"net"
	"os"
	"time"

	"github.com/konglong147/securefile/adapter"
	"github.com/konglong147/securefile/local/sing/common"
	"github.com/konglong147/securefile/local/sing/common/buf"
	"github.com/konglong147/securefile/local/sing/common/control"
	E "github.com/konglong147/securefile/local/sing/common/exceptions"
	M "github.com/konglong147/securefile/local/sing/common/metadata"
	N "github.com/konglong147/securefile/local/sing/common/network"
)

func (a *theLibaoziwenzi) tingxieDpus() (net.PacketConn, error) {
	bindAddr := M.SocksaddrFrom(a.tingshuoCanshu.Listen.Build(), a.tingshuoCanshu.ListenPort)
	var lc net.ListenConfig
	var udpFragment bool
	if a.tingshuoCanshu.UDPFragment != nil {
		udpFragment = *a.tingshuoCanshu.UDPFragment
	} else {
		udpFragment = a.tingshuoCanshu.UDPFragmentDefault
	}
	if !udpFragment {
		lc.Control = control.Append(lc.Control, control.DisableUDPFragment())
	}
	odeonnoCnet, err := lc.ListenPacket(a.ctx, M.NetworkFromNetAddr(N.NetworkUDP, bindAddr.Addr), bindAddr.String())
	if err != nil {
		return nil, err
	}
	a.odeonnoCnet = odeonnoCnet.(*net.UDPConn)
	a.udpAddr = bindAddr
	a.logger.Info("udp server started at ", odeonnoCnet.LocalAddr())
	return odeonnoCnet, err
}

func (a *theLibaoziwenzi) tingxielpsea() {
	defer close(a.packetOutboundClosed)
	buffer := buf.NewPacket()
	defer buffer.Release()
	buffer.IncRef()
	defer buffer.DecRef()
	packetService := (*myInboundPacketAdapter)(a)
	for {
		buffer.Reset()
		n, addr, err := a.odeonnoCnet.ReadFromUDPAddrPort(buffer.FreeBytes())
		if err != nil {
			return
		}
		buffer.Truncate(n)
		var metadata adapter.InboundContext
		metadata.Inbound = a.tag
		metadata.InboundType = a.protocol
		metadata.InboundOptions = a.tingshuoCanshu.InboundOptions
		metadata.Source = M.SocksaddrFromNetIP(addr).Unwrap()
		metadata.OriginDestination = a.udpAddr
		err = a.packetHandler.NewPacket(a.ctx, packetService, buffer, metadata)
		if err != nil {
			a.newError(E.Cause(err, "process packet from ", metadata.Source))
		}
	}
}

func (a *theLibaoziwenzi) loopUDPOOBIn() {
	defer close(a.packetOutboundClosed)
	buffer := buf.NewPacket()
	defer buffer.Release()
	buffer.IncRef()
	defer buffer.DecRef()
	packetService := (*myInboundPacketAdapter)(a)
	oob := make([]byte, 1024)
	for {
		buffer.Reset()
		n, oobN, _, addr, err := a.odeonnoCnet.ReadMsgUDPAddrPort(buffer.FreeBytes(), oob)
		if err != nil {
			return
		}
		buffer.Truncate(n)
		var metadata adapter.InboundContext
		metadata.Inbound = a.tag
		metadata.InboundType = a.protocol
		metadata.InboundOptions = a.tingshuoCanshu.InboundOptions
		metadata.Source = M.SocksaddrFromNetIP(addr).Unwrap()
		metadata.OriginDestination = a.udpAddr
		err = a.oobPacketHandler.NewPacket(a.ctx, packetService, buffer, oob[:oobN], metadata)
		if err != nil {
			a.newError(E.Cause(err, "process packet from ", metadata.Source))
		}
	}
}

func (a *theLibaoziwenzi) tingxielpseaThreadSafe() {
	defer close(a.packetOutboundClosed)
	packetService := (*myInboundPacketAdapter)(a)
	for {
		buffer := buf.NewPacket()
		n, addr, err := a.odeonnoCnet.ReadFromUDPAddrPort(buffer.FreeBytes())
		if err != nil {
			buffer.Release()
			return
		}
		buffer.Truncate(n)
		var metadata adapter.InboundContext
		metadata.Inbound = a.tag
		metadata.InboundType = a.protocol
		metadata.InboundOptions = a.tingshuoCanshu.InboundOptions
		metadata.Source = M.SocksaddrFromNetIP(addr).Unwrap()
		metadata.OriginDestination = a.udpAddr
		err = a.packetHandler.NewPacket(a.ctx, packetService, buffer, metadata)
		if err != nil {
			buffer.Release()
			a.newError(E.Cause(err, "process packet from ", metadata.Source))
		}
	}
}

func (a *theLibaoziwenzi) loopUDPOOBInThreadSafe() {
	defer close(a.packetOutboundClosed)
	packetService := (*myInboundPacketAdapter)(a)
	oob := make([]byte, 1024)
	for {
		buffer := buf.NewPacket()
		n, oobN, _, addr, err := a.odeonnoCnet.ReadMsgUDPAddrPort(buffer.FreeBytes(), oob)
		if err != nil {
			buffer.Release()
			return
		}
		buffer.Truncate(n)
		var metadata adapter.InboundContext
		metadata.Inbound = a.tag
		metadata.InboundType = a.protocol
		metadata.InboundOptions = a.tingshuoCanshu.InboundOptions
		metadata.Source = M.SocksaddrFromNetIP(addr).Unwrap()
		metadata.OriginDestination = a.udpAddr
		err = a.oobPacketHandler.NewPacket(a.ctx, packetService, buffer, oob[:oobN], metadata)
		if err != nil {
			buffer.Release()
			a.newError(E.Cause(err, "process packet from ", metadata.Source))
		}
	}
}

func (a *theLibaoziwenzi) loopUDPOut() {
	for {
		select {
		case packet := <-a.packetOutbound:
			err := a.writePacket(packet.buffer, packet.destination)
			if err != nil && !E.IsClosed(err) {
				a.newError(E.New("write back udp: ", err))
			}
			continue
		case <-a.packetOutboundClosed:
		}
		for {
			select {
			case packet := <-a.packetOutbound:
				packet.buffer.Release()
			default:
				return
			}
		}
	}
}

func (a *theLibaoziwenzi) writePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	if destination.IsFqdn() {
		udpAddr, err := net.ResolveUDPAddr(N.NetworkUDP, destination.String())
		if err != nil {
			return err
		}
		return common.Error(a.odeonnoCnet.WriteTo(buffer.Bytes(), udpAddr))
	}
	return common.Error(a.odeonnoCnet.WriteToUDPAddrPort(buffer.Bytes(), destination.AddrPort()))
}

type myInboundPacketAdapter theLibaoziwenzi

func (s *myInboundPacketAdapter) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	n, addr, err := s.odeonnoCnet.ReadFromUDPAddrPort(buffer.FreeBytes())
	if err != nil {
		return M.Socksaddr{}, err
	}
	buffer.Truncate(n)
	return M.SocksaddrFromNetIP(addr), nil
}

func (s *myInboundPacketAdapter) WriteIsThreadUnsafe() {
}

type myInboundPacket struct {
	buffer      *buf.Buffer
	destination M.Socksaddr
}

func (s *myInboundPacketAdapter) Upstream() any {
	return s.odeonnoCnet
}

func (s *myInboundPacketAdapter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	select {
	case s.packetOutbound <- &myInboundPacket{buffer, destination}:
		return nil
	case <-s.packetOutboundClosed:
		return os.ErrClosed
	}
}

func (s *myInboundPacketAdapter) Close() error {
	return s.odeonnoCnet.Close()
}

func (s *myInboundPacketAdapter) LocalAddr() net.Addr {
	return s.odeonnoCnet.LocalAddr()
}

func (s *myInboundPacketAdapter) SetDeadline(t time.Time) error {
	return s.odeonnoCnet.SetDeadline(t)
}

func (s *myInboundPacketAdapter) SetReadDeadline(t time.Time) error {
	return s.odeonnoCnet.SetReadDeadline(t)
}

func (s *myInboundPacketAdapter) SetWriteDeadline(t time.Time) error {
	return s.odeonnoCnet.SetWriteDeadline(t)
}
