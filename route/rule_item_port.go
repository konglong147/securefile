package route

import (
	"strings"

	"github.com/konglong147/securefile/adapter"
	F "github.com/konglong147/securefile/local/sing/common/format"
)

var _ RuleItem = (*JiekouMetise)(nil)

type JiekouMetise struct {
	ports    []uint16
	portMap  map[uint16]bool
	isSource bool
}

func NewJiekouMetise(isSource bool, ports []uint16) *JiekouMetise {
	portMap := make(map[uint16]bool)
	for _, port := range ports {
		portMap[port] = true
	}
	return &JiekouMetise{
		ports:    ports,
		portMap:  portMap,
		isSource: isSource,
	}
}

func (r *JiekouMetise) Match(metadata *adapter.InboundContext) bool {
	if r.isSource {
		return r.portMap[metadata.Source.Port]
	} else {
		return r.portMap[metadata.Destination.Port]
	}
}

func (r *JiekouMetise) String() string {
	var description string
	if r.isSource {
		description = "source_port="
	} else {
		description = "port="
	}
	pLen := len(r.ports)
	if pLen == 1 {
		description += F.ToString(r.ports[0])
	} else {
		description += "[" + strings.Join(F.MapToString(r.ports), " ") + "]"
	}
	return description
}
