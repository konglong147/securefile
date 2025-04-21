//go:build !linux

package redir

import (
	"net/netip"
	"os"

	"github.com/konglong147/securefile/local/sing/common/control"
)

func TProxy(fd uintptr, isIPv6 bool) error {
	return os.ErrInvalid
}

func TProxyWriteBack() control.Func {
	return nil
}

func GetOriginalDestinationFromOOB(oob []byte) (netip.AddrPort, error) {
	return netip.AddrPort{}, os.ErrInvalid
}
