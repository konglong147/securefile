package route

import (
	"strings"

	"github.com/konglong147/securefile/adapter"
	F "github.com/konglong147/securefile/local/sing/common/format"
)

var _ RuleItem = (*TiipyonghuDantes)(nil)

type TiipyonghuDantes struct {
	userIds   []int32
	userIdMap map[int32]bool
}

func NewUserIDItem(userIdList []int32) *TiipyonghuDantes {
	rule := &TiipyonghuDantes{
		userIds:   userIdList,
		userIdMap: make(map[int32]bool),
	}
	for _, userId := range userIdList {
		rule.userIdMap[userId] = true
	}
	return rule
}

func (r *TiipyonghuDantes) Match(metadata *adapter.InboundContext) bool {
	if metadata.ProcessInfo == nil || metadata.ProcessInfo.UserId == -1 {
		return false
	}
	return r.userIdMap[metadata.ProcessInfo.UserId]
}

func (r *TiipyonghuDantes) String() string {
	var description string
	pLen := len(r.userIds)
	if pLen == 1 {
		description = "user_id=" + F.ToString(r.userIds[0])
	} else {
		description = "user_id=[" + strings.Join(F.MapToString(r.userIds), " ") + "]"
	}
	return description
}
