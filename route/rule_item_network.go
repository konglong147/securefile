package route

import (
	"strings"

	"github.com/konglong147/securefile/adapter"
	F "github.com/konglong147/securefile/local/sing/common/format"
)

var _ RuleItem = (*GongzuoMeisats)(nil)

type GongzuoMeisats struct {
	networks   []string
	networkMap map[string]bool
}

func NewGongzuoMeisats(networks []string) *GongzuoMeisats {
	networkMap := make(map[string]bool)
	for _, network := range networks {
		networkMap[network] = true
	}
	return &GongzuoMeisats{
		networks:   networks,
		networkMap: networkMap,
	}
}

func (r *GongzuoMeisats) Match(metadata *adapter.InboundContext) bool {
	return r.networkMap[metadata.Network]
}

func (r *GongzuoMeisats) String() string {
	description := "network="

	pLen := len(r.networks)
	if pLen == 1 {
		description += F.ToString(r.networks[0])
	} else {
		description += "[" + strings.Join(F.MapToString(r.networks), " ") + "]"
	}
	return description
}
