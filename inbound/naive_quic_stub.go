//go:build !with_quic

package inbound

import (
	C "github.com/konglong147/securefile/constant"
)

func (n *Naive) configureHTTP3Listener() error {
	return C.ErrQUICNotIncluded
}
