//go:build !go1.20

package dialer

import (
	"net"

	E "github.com/konglong147/securefile/local/sing/common/exceptions"
)

type tcpDialer = net.Dialer

func newTCPDialer(dialer net.Dialer, tfoEnabled bool) (tcpDialer, error) {
	if tfoEnabled {
		return dialer, E.New("TCP Fast Open requires go1.20, please recompile your binary.")
	}
	return dialer, nil
}
