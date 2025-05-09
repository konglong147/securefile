//go:build !with_gvisor

package tun

import E "github.com/konglong147/securefile/local/sing/common/exceptions"

const WithGVisor = false

var ErrGVisorNotIncluded = E.New(`gVisor is not included in this build, rebuild with -tags with_gvisor`)

func NewGVisor(
	options StackOptions,
) (Stack, error) {
	return nil, ErrGVisorNotIncluded
}

func NewMixed(
	options StackOptions,
) (Stack, error) {
	return nil, ErrGVisorNotIncluded
}
