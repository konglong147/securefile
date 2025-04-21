package route

import (
	"strings"

	"github.com/konglong147/securefile/adapter"
	F "github.com/konglong147/securefile/local/sing/common/format"
)

var _ RuleItem = (*WaizileixingMests)(nil)

type WaizileixingMests struct {
	outbounds   []string
	outboundMap map[string]bool
	matchAny    bool
}

func NewOutboundRule(outbounds []string) *WaizileixingMests {
	rule := &WaizileixingMests{outbounds: outbounds, outboundMap: make(map[string]bool)}
	for _, outbound := range outbounds {
		if outbound == "any" {
			rule.matchAny = true
		} else {
			rule.outboundMap[outbound] = true
		}
	}
	return rule
}

func (r *WaizileixingMests) Match(metadata *adapter.InboundContext) bool {
	if r.matchAny && metadata.Outbound != "" {
		return true
	}
	return r.outboundMap[metadata.Outbound]
}

func (r *WaizileixingMests) String() string {
	if len(r.outbounds) == 1 {
		return F.ToString("outbound=", r.outbounds[0])
	} else {
		return F.ToString("outbound=[", strings.Join(r.outbounds, " "), "]")
	}
}
