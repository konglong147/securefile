package control

import (
	"encoding/binary"
	"net/netip"
	"syscall"

	E "github.com/konglong147/securefile/local/sing/common/exceptions"
	M "github.com/konglong147/securefile/local/sing/common/metadata"

	"golang.org/x/sys/unix"
)

func TProxy(fd uintptr, family int) error {
	err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	if err == nil {
		err = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
	}
	if err == nil && family == unix.AF_INET6 {
		err = syscall.SetsockoptInt(int(fd), syscall.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
	}
	if err == nil {
		err = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_RECVORIGDSTADDR, 1)
	}
	if err == nil && family == unix.AF_INET6 {
		err = syscall.SetsockoptInt(int(fd), syscall.SOL_IPV6, unix.IPV6_RECVORIGDSTADDR, 1)
	}
	return err
}

func TProxyWriteBack() Func {
	return func(network, address string, conn syscall.RawConn) error {
		return Raw(conn, func(fd uintptr) error {
			if M.ParseSocksaddr(address).Addr.Is6() {
				return syscall.SetsockoptInt(int(fd), syscall.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
			} else {
				return syscall.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
			}
		})
	}
}

func GetOriginalDestinationFromOOB(oob []byte) (netip.AddrPort, error) {
	controlMessages, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return netip.AddrPort{}, err
	}
	for _, message := range controlMessages {
		if message.Header.Level == unix.SOL_IP && message.Header.Type == unix.IP_RECVORIGDSTADDR {
			return netip.AddrPortFrom(M.AddrFromIP(message.Data[4:8]), binary.BigEndian.Uint16(message.Data[2:4])), nil
		} else if message.Header.Level == unix.SOL_IPV6 && message.Header.Type == unix.IPV6_RECVORIGDSTADDR {
			return netip.AddrPortFrom(M.AddrFromIP(message.Data[8:24]), binary.BigEndian.Uint16(message.Data[2:4])), nil
		}
	}
	return netip.AddrPort{}, E.New("not found")
}
