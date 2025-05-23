package route

import (
	"net/netip"

	"github.com/konglong147/securefile/adapter"
	N "github.com/konglong147/securefile/local/sing/common/network"
)

var _ RuleItem = (*IPIsPrivateItem)(nil)

type IPIsPrivateItem struct {
	isSource bool
}

func NewIPIsPrivateItem(isSource bool) *IPIsPrivateItem {
	return &IPIsPrivateItem{isSource}
}

func (r *IPIsPrivateItem) Match(metadata *adapter.InboundContext) bool {
	var destination netip.Addr
	if r.isSource {
		destination = metadata.Source.Addr
	} else {
		destination = metadata.Destination.Addr
	}
	if destination.IsValid() {
		return !N.IsPublicAddr(destination)
	}
	if !r.isSource {
		for _, destinationAddress := range metadata.DestinationAddresses {
			if !N.IsPublicAddr(destinationAddress) {
				return true
			}
		}
	}
	return false
}

func (r *IPIsPrivateItem) String() string {
	if r.isSource {
		return "source_ip_is_private=true"
	} else {
		return "ip_is_private=true"
	}
}
