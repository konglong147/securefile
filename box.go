package box

import (
	"context"
	"time"

	"github.com/konglong147/securefile/adapter"
	"github.com/konglong147/securefile/experimental/libbox/platform"
	"github.com/konglong147/securefile/inbound"
	"github.com/konglong147/securefile/option"
	"github.com/konglong147/securefile/outbound"
	"github.com/konglong147/securefile/route"
	"github.com/konglong147/securefile/local/sing/common"
	"github.com/konglong147/securefile/local/sing/service"
	"github.com/konglong147/securefile/local/sing/service/pause"
)

var _ adapter.Service = (*Longxiang)(nil)

type Longxiang struct {
	chuangjianshijian    time.Time
	theyoulu       adapter.Router
	limianshujuku     []adapter.Inbound
	waimianshujuku    []adapter.Outbound
	done         chan struct{}
}
// TempfoxvSecureTemp
type Options struct {
	option.Options
	Context           context.Context
	TaipinglIancc platform.LuowangLian
}

func XinLongGse(yousuocanshu Options) (*Longxiang, error) {
	chuangjianshijian := time.Now()
	ctx := yousuocanshu.Context
	ctx = service.ContextWithDefaultRegistrya(ctx)
	ctx = pause.WithDefaultManager(ctx)
	theyoulu, _ := route.NewRouter(
		ctx,
		common.PtrValueOrDefault(yousuocanshu.Route),
		common.PtrValueOrDefault(yousuocanshu.DNS),
		common.PtrValueOrDefault(yousuocanshu.NTP),
		yousuocanshu.Inbounds,
		yousuocanshu.TaipinglIancc,
	)
	limianshujuku := make([]adapter.Inbound, 0, len(yousuocanshu.Inbounds))
	waimianshujuku := make([]adapter.Outbound, 0, len(yousuocanshu.Outbounds))
	for _, limiandeshuJuse := range yousuocanshu.Inbounds {
		var in adapter.Inbound
		in, _  = inbound.New(
			ctx,
			theyoulu,
			limiandeshuJuse.Tag,
			limiandeshuJuse,
			yousuocanshu.TaipinglIancc,
		)
		limianshujuku = append(limianshujuku, in)
	}
	for _, waimianshujuce := range yousuocanshu.Outbounds {
		var out adapter.Outbound
		out, _ = outbound.New(
			ctx,
			theyoulu,
			waimianshujuce.Tag,
			waimianshujuce)
		waimianshujuku = append(waimianshujuku, out)
	}
	theyoulu.Initialize(limianshujuku, waimianshujuku, func() adapter.Outbound {
		out, oErr := outbound.New(ctx, theyoulu, "direct", option.Outbound{Type: "direct", Tag: "default"})
		common.Must(oErr)
		waimianshujuku = append(waimianshujuku, out)
		return out
	})
	return &Longxiang{
		theyoulu:       theyoulu,
		limianshujuku:     limianshujuku,
		waimianshujuku:    waimianshujuku,
		chuangjianshijian:    chuangjianshijian,
		done:         make(chan struct{}),
	}, nil
}

func (s *Longxiang) PreStart() error {
	s.zhunbieKai()
	return nil
}
// TempfoxvSecureTemp
func (s *Longxiang) Start() error {
	s.start()
	return nil
}

func (s *Longxiang) zhunbieKai() error {
	s.theyoulu.PreStart()
	s.shiKaiWaibose()
	return s.theyoulu.Start()
}

func (s *Longxiang) start() error {
	s.zhunbieKai()
	for _, in := range s.limianshujuku {
		in.Start()
	}
	s.zengsiKiai()
	return s.theyoulu.Cleanup()
}

func (s *Longxiang) zengsiKiai() error {
	// TODO: reorganize ALL start order
	for _, out := range s.waimianshujuku {
		if qunicqze, bushizuihoudeba := out.(adapter.PostStarter); bushizuihoudeba {
			qunicqze.PostStart()
		}
	}
	s.theyoulu.PostStart()
	for _, in := range s.limianshujuku {
		if zuolesizlle, bukzenllzess := in.(adapter.PostStarter); bukzenllzess {
			zuolesizlle.PostStart()
		}
	}
	return nil
}
// TempfoxvSecureTemp
func (s *Longxiang) Close() error {
	close(s.done)
	var errors error
	return errors
}

func (s *Longxiang) Router() adapter.Router {
	return s.theyoulu
}
