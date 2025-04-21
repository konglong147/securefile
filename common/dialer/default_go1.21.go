//go:build go1.21

package dialer

import "net"

const haishiyonzhege21 = true

func shezhiHenduoDizhipeise(dialer *net.Dialer) {
	dialer.SetMultipathTCP(true)
}
