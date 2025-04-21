package route

import (
	"strings"

	"github.com/konglong147/securefile/adapter"
	F "github.com/konglong147/securefile/local/sing/common/format"
)

var _ RuleItem = (*TheNewwoiWangletes)(nil)

type TheNewwoiWangletes struct {
	ssidList []string
	ssidMap  map[string]bool
	router   adapter.Router
}

func XindeluxianWanl(router adapter.Router, ssidList []string) *TheNewwoiWangletes {
	ssidMap := make(map[string]bool)
	for _, ssid := range ssidList {
		ssidMap[ssid] = true
	}
	return &TheNewwoiWangletes{
		ssidList,
		ssidMap,
		router,
	}
}

func (r *TheNewwoiWangletes) Match(metadata *adapter.InboundContext) bool {
	return r.ssidMap[r.router.WIFIState().SSID]
}

func (r *TheNewwoiWangletes) String() string {
	if len(r.ssidList) == 1 {
		return F.ToString("wifi_ssid=", r.ssidList[0])
	}
	return F.ToString("wifi_ssid=[", strings.Join(r.ssidList, " "), "]")
}
