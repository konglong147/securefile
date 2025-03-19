//go:build !(darwin || linux)

package Foxboxvpn

import "os"

func getTunnelName(fd int32) (string, error) {
	return "", os.ErrInvalid
}
