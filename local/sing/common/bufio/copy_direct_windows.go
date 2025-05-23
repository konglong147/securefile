package bufio

import (
	"io"
	"net/netip"
	"os"
	"syscall"

	"github.com/konglong147/securefile/local/sing/common/buf"
	E "github.com/konglong147/securefile/local/sing/common/exceptions"
	M "github.com/konglong147/securefile/local/sing/common/metadata"
	N "github.com/konglong147/securefile/local/sing/common/network"

	"golang.org/x/sys/windows"
)

var _ N.ReadWaiter = (*syscallReadWaiter)(nil)

type syscallReadWaiter struct {
	rawConn  syscall.RawConn
	readErr  error
	readFunc func(fd uintptr) (done bool)
	hasData  bool
	buffer   *buf.Buffer
	options  N.ReadWaitOptions
}

func createSyscallReadWaiter(reader any) (*syscallReadWaiter, bool) {
	if syscallConn, isSyscallConn := reader.(syscall.Conn); isSyscallConn {
		rawConn, err := syscallConn.SyscallConn()
		if err == nil {
			return &syscallReadWaiter{rawConn: rawConn}, true
		}
	}
	return nil, false
}

func (w *syscallReadWaiter) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	w.options = options
	w.readFunc = func(fd uintptr) (done bool) {
		if !w.hasData {
			w.hasData = true
			// golang's internal/poll.FD.RawRead will Use a zero-byte read as a way to get notified when this
			// socket is readable if we return false. So the `recv` syscall will not block the system thread.
			return false
		}
		buffer := w.options.NewBuffer()
		var readN int32
		readN, w.readErr = recv(windows.Handle(fd), buffer.FreeBytes(), 0)
		if readN > 0 {
			buffer.Truncate(int(readN))
			w.options.PostReturn(buffer)
			w.buffer = buffer
		} else {
			buffer.Release()
		}
		if w.readErr == windows.WSAEWOULDBLOCK {
			return false
		}
		if readN == 0 && w.readErr == nil {
			w.readErr = io.EOF
		}
		w.hasData = false
		return true
	}
	return false
}

func (w *syscallReadWaiter) WaitReadBuffer() (buffer *buf.Buffer, err error) {
	if w.readFunc == nil {
		return nil, os.ErrInvalid
	}
	err = w.rawConn.Read(w.readFunc)
	if err != nil {
		return
	}
	if w.readErr != nil {
		if w.readErr == io.EOF {
			return nil, io.EOF
		}
		return nil, E.Cause(w.readErr, "raw read")
	}
	buffer = w.buffer
	w.buffer = nil
	return
}

var _ N.PacketReadWaiter = (*syscallPacketReadWaiter)(nil)

type syscallPacketReadWaiter struct {
	rawConn  syscall.RawConn
	readErr  error
	readFrom M.Socksaddr
	readFunc func(fd uintptr) (done bool)
	hasData  bool
	buffer   *buf.Buffer
	options  N.ReadWaitOptions
}

func createSyscallPacketReadWaiter(reader any) (*syscallPacketReadWaiter, bool) {
	if syscallConn, isSyscallConn := reader.(syscall.Conn); isSyscallConn {
		rawConn, err := syscallConn.SyscallConn()
		if err == nil {
			return &syscallPacketReadWaiter{rawConn: rawConn}, true
		}
	}
	return nil, false
}

func (w *syscallPacketReadWaiter) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	w.options = options
	w.readFunc = func(fd uintptr) (done bool) {
		if !w.hasData {
			w.hasData = true
			// golang's internal/poll.FD.RawRead will Use a zero-byte read as a way to get notified when this
			// socket is readable if we return false. So the `recvfrom` syscall will not block the system thread.
			return false
		}
		buffer := w.options.NewPacketBuffer()
		var readN int
		var from windows.Sockaddr
		readN, from, w.readErr = windows.Recvfrom(windows.Handle(fd), buffer.FreeBytes(), 0)
		if readN > 0 {
			buffer.Truncate(readN)
			w.options.PostReturn(buffer)
			w.buffer = buffer
		} else {
			buffer.Release()
		}
		if w.readErr == windows.WSAEWOULDBLOCK {
			return false
		}
		if from != nil {
			switch fromAddr := from.(type) {
			case *windows.SockaddrInet4:
				w.readFrom = M.SocksaddrFrom(netip.AddrFrom4(fromAddr.Addr), uint16(fromAddr.Port))
			case *windows.SockaddrInet6:
				w.readFrom = M.SocksaddrFrom(netip.AddrFrom16(fromAddr.Addr), uint16(fromAddr.Port)).Unwrap()
			}
		}
		w.hasData = false
		return true
	}
	return false
}

func (w *syscallPacketReadWaiter) WaitReadPacket() (buffer *buf.Buffer, destination M.Socksaddr, err error) {
	if w.readFunc == nil {
		return nil, M.Socksaddr{}, os.ErrInvalid
	}
	err = w.rawConn.Read(w.readFunc)
	if err != nil {
		return
	}
	if w.readErr != nil {
		err = E.Cause(w.readErr, "raw read")
		return
	}
	buffer = w.buffer
	w.buffer = nil
	destination = w.readFrom
	return
}
