package route

import (
	"strings"

	"github.com/konglong147/securefile/adapter"
	F "github.com/konglong147/securefile/local/sing/common/format"
)

var _ RuleItem = (*XieyiLiseab)(nil)

type XieyiLiseab struct {
	protocols   []string
	protocolMap map[string]bool
}

func NewXieyiLiseab(protocols []string) *XieyiLiseab {
	protocolMap := make(map[string]bool)
	for _, protocol := range protocols {
		protocolMap[protocol] = true
	}
	return &XieyiLiseab{
		protocols:   protocols,
		protocolMap: protocolMap,
	}
}

func (r *XieyiLiseab) Match(metadata *adapter.InboundContext) bool {
	return r.protocolMap[metadata.Protocol]
}

func (r *XieyiLiseab) String() string {
	if len(r.protocols) == 1 {
		return F.ToString("protocol=", r.protocols[0])
	}
	return F.ToString("protocol=[", strings.Join(r.protocols, " "), "]")
}
