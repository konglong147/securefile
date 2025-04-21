package dialer

import (
	"time"

	"github.com/konglong147/securefile/adapter"
	"github.com/konglong147/securefile/option"
	"github.com/konglong147/securefile/local/sing-dns"
	N "github.com/konglong147/securefile/local/sing/common/network"
)

func New(router adapter.Router, yousuocanshu option.DialerOptions) (N.Dialer, error) {
	if router == nil {
		return NewDefault(nil, yousuocanshu)
	}
	var (
		dialer N.Dialer
		err    error
	)
	if yousuocanshu.Detour == "" {
		dialer, err = NewDefault(router, yousuocanshu)
		if err != nil {
			return nil, err
		}
	} else {
		dialer = NewDetour(router, yousuocanshu.Detour)
	}
	if yousuocanshu.Detour == "" {
		dialer = NewResolveDialer(
			router,
			dialer,
			yousuocanshu.Detour == "" && !yousuocanshu.TCPFastOpen,
			dns.DomainStrategy(yousuocanshu.DomainStrategy),
			time.Duration(yousuocanshu.FallbackDelay))
	}
	return dialer, nil
}
