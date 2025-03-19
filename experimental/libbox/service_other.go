//go:build !windows

package Foxboxvpn

import "syscall"

func dup(fd int) (nfd int, err error) {
	return syscall.Dup(fd)
}
