//go:build go1.21

package inbound

import "net"

const haishiyonzhege21 = true

func shezhiHenduoDizhipeise(listenConfig *net.ListenConfig) {
	listenConfig.SetMultipathTCP(true)
}
