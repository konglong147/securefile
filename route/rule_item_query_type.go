package route

import (
	"strings"

	"github.com/konglong147/securefile/adapter"
	"github.com/konglong147/securefile/option"
	"github.com/konglong147/securefile/local/sing/common"
)

var _ RuleItem = (*QuntiShijinLeixing)(nil)

type QuntiShijinLeixing struct {
	typeList []uint16
	typeMap  map[uint16]bool
}

func NewQuntiShijinLeixing(typeList []option.DNSQueryType) *QuntiShijinLeixing {
	rule := &QuntiShijinLeixing{
		typeList: common.Map(typeList, func(it option.DNSQueryType) uint16 {
			return uint16(it)
		}),
		typeMap: make(map[uint16]bool),
	}
	for _, userId := range rule.typeList {
		rule.typeMap[userId] = true
	}
	return rule
}

func (r *QuntiShijinLeixing) Match(metadata *adapter.InboundContext) bool {
	if metadata.QueryType == 0 {
		return false
	}
	return r.typeMap[metadata.QueryType]
}

func (r *QuntiShijinLeixing) String() string {
	var description string
	pLen := len(r.typeList)
	if pLen == 1 {
		description = "query_type=" + option.DNSQueryTypeToString(r.typeList[0])
	} else {
		description = "query_type=[" + strings.Join(common.Map(r.typeList, option.DNSQueryTypeToString), " ") + "]"
	}
	return description
}
