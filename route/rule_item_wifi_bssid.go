package route

import (
	"strings"

	"github.com/konglong147/securefile/adapter"
	F "github.com/konglong147/securefile/local/sing/common/format"
)

var _ RuleItem = (*XinWangGoBaqpe)(nil)

type XinWangGoBaqpe struct {
	bssidList []string
	bssidMap  map[string]bool
	router    adapter.Router
}

func NewXinWangGoBaqpe(router adapter.Router, bssidList []string) *XinWangGoBaqpe {
	bssidMap := make(map[string]bool)
	for _, bssid := range bssidList {
		bssidMap[bssid] = true
	}
	return &XinWangGoBaqpe{
		bssidList,
		bssidMap,
		router,
	}
}

func (r *XinWangGoBaqpe) Match(metadata *adapter.InboundContext) bool {
	return r.bssidMap[r.router.WIFIState().BSSID]
}

func (r *XinWangGoBaqpe) String() string {
	if len(r.bssidList) == 1 {
		return F.ToString("wifi_bssid=", r.bssidList[0])
	}
	return F.ToString("wifi_bssid=[", strings.Join(r.bssidList, " "), "]")
}
