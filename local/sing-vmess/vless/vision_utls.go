//go:build with_utls

package vless

import (
	"net"
	"reflect"
	"unsafe"

	"github.com/konglong147/securefile/local/sing/common"
	utls "github.com/sagernet/utls"
)

func init() {
	tlsRegistry = append(tlsRegistry, func(conn net.Conn) (loaded bool, netConn net.Conn, reflectType reflect.Type, reflectPointer uintptr) {
		tlsConn, loaded := common.Cast[*utls.UConn](conn)
		if !loaded {
			return
		}
		return true, tlsConn.NetConn(), reflect.TypeOf(tlsConn.Conn).Elem(), uintptr(unsafe.Pointer(tlsConn.Conn))
	})
}
