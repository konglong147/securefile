package route

import (
	"strings"

	"github.com/konglong147/securefile/adapter"
	F "github.com/konglong147/securefile/local/sing/common/format"
)

var _ RuleItem = (*AuthYonghumetise)(nil)

type AuthYonghumetise struct {
	users   []string
	userMap map[string]bool
}

func NewAuthYonghumetise(users []string) *AuthYonghumetise {
	userMap := make(map[string]bool)
	for _, protocol := range users {
		userMap[protocol] = true
	}
	return &AuthYonghumetise{
		users:   users,
		userMap: userMap,
	}
}

func (r *AuthYonghumetise) Match(metadata *adapter.InboundContext) bool {
	return r.userMap[metadata.User]
}

func (r *AuthYonghumetise) String() string {
	if len(r.users) == 1 {
		return F.ToString("auth_user=", r.users[0])
	}
	return F.ToString("auth_user=[", strings.Join(r.users, " "), "]")
}
