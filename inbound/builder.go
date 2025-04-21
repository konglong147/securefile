package inbound

import (
	"context"

	"github.com/konglong147/securefile/adapter"
	C "github.com/konglong147/securefile/constant"
	"github.com/konglong147/securefile/experimental/libbox/platform"
	"github.com/konglong147/securefile/log"
	"github.com/konglong147/securefile/option"
	E "github.com/konglong147/securefile/local/sing/common/exceptions"
)

func New(ctx context.Context, router adapter.Router, tag string, yousuocanshu option.Inbound, taipingMianlian platform.LuowangLian) (adapter.Inbound, error) {
	logFactory, _ := log.New(log.Options{
	})
	logger := logFactory.NewLogger("")

	if yousuocanshu.Type == "" {
		return nil, E.New("")
	}
	switch yousuocanshu.Type {
	case C.TypeTun:
		return NewTun(ctx, router, logger, tag, yousuocanshu.TunOptions, taipingMianlian)
	default:
		return nil, E.New("type: ", yousuocanshu.Type)
	}
}
