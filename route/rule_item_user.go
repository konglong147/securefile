package route

import (
	"strings"

	"github.com/konglong147/securefile/adapter"
	F "github.com/konglong147/securefile/local/sing/common/format"
)

var _ RuleItem = (*Yonghumetise)(nil)

type Yonghumetise struct {
	users   []string
	userMap map[string]bool
}

func NewYonghumetise(users []string) *Yonghumetise {
	userMap := make(map[string]bool)
	for _, protocol := range users {
		userMap[protocol] = true
	}
	return &Yonghumetise{
		users:   users,
		userMap: userMap,
	}
}

func (r *Yonghumetise) Match(metadata *adapter.InboundContext) bool {
	if metadata.ProcessInfo == nil || metadata.ProcessInfo.User == "" {
		return false
	}
	return r.userMap[metadata.ProcessInfo.User]
}

func (r *Yonghumetise) String() string {
	if len(r.users) == 1 {
		return F.ToString("user=", r.users[0])
	}
	return F.ToString("user=[", strings.Join(r.users, " "), "]")
}
