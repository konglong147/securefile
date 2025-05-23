package deadline

import (
	"github.com/konglong147/securefile/local/sing/common"
	N "github.com/konglong147/securefile/local/sing/common/network"
)

type WithoutReadDeadline interface {
	NeedAdditionalReadDeadline() bool
}

func NeedAdditionalReadDeadline(rawReader any) bool {
	if deadlineReader, loaded := rawReader.(WithoutReadDeadline); loaded {
		return deadlineReader.NeedAdditionalReadDeadline()
	}
	if upstream, hasUpstream := rawReader.(N.WithUpstreamReader); hasUpstream {
		return NeedAdditionalReadDeadline(upstream.UpstreamReader())
	}
	if upstream, hasUpstream := rawReader.(common.WithUpstream); hasUpstream {
		return NeedAdditionalReadDeadline(upstream.Upstream())
	}
	return false
}
