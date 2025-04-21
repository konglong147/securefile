package route

import (
	"strings"

	"github.com/konglong147/securefile/adapter"
	E "github.com/konglong147/securefile/local/sing/common/exceptions"
)

var _ RuleItem = (*NaliZuoxiaozmose)(nil)

type NaliZuoxiaozmose struct {
	router   adapter.Router
	codes    []string
	matchers []adapter.Rule
}

func NewNaliZuoxiaozmose(router adapter.Router, codes []string) *NaliZuoxiaozmose {
	return &NaliZuoxiaozmose{
		router: router,
		codes:  codes,
	}
}

func (r *NaliZuoxiaozmose) Update() error {
	matchers := make([]adapter.Rule, 0, len(r.codes))
	for _, code := range r.codes {
		matcher, err := r.router.LoadGeosite(code)
		if err != nil {
			return E.Cause(err, "read geosite")
		}
		matchers = append(matchers, matcher)
	}
	r.matchers = matchers
	return nil
}

func (r *NaliZuoxiaozmose) Match(metadata *adapter.InboundContext) bool {
	for _, matcher := range r.matchers {
		if matcher.Match(metadata) {
			return true
		}
	}
	return false
}

func (r *NaliZuoxiaozmose) String() string {
	description := "geosite="
	cLen := len(r.codes)
	if cLen == 1 {
		description += r.codes[0]
	} else if cLen > 3 {
		description += "[" + strings.Join(r.codes[:3], " ") + "...]"
	} else {
		description += "[" + strings.Join(r.codes, " ") + "]"
	}
	return description
}
