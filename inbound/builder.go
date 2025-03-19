package inbound

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/libbox/platform"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func New(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.Inbound, platformInterface platform.Interface) (adapter.Inbound, error) {
	if options.Type == "" {
		return nil, E.New("missing inbound type")
	}
	switch options.Type {
	case C.TypeTun:
		return NewTun(ctx, router, logger, tag, options.TunOptions, platformInterface)
	case C.TypeRedirect:
		return NewRedirect(ctx, router, logger, tag, options.RedirectOptions), nil
	case C.TypeTProxy:
		return NewTProxy(ctx, router, logger, tag, options.TProxyOptions), nil
	case C.TypeDirect:
		return NewDirect(ctx, router, logger, tag, options.DirectOptions), nil
	case C.TypeSOCKS:
		return NewSocks(ctx, router, logger, tag, options.SocksOptions), nil
	case C.TypeHTTP:
		return NewHTTP(ctx, router, logger, tag, options.HTTPOptions)
	case C.TypeMixed:
		return NewMixed(ctx, router, logger, tag, options.MixedOptions), nil
	case C.TypeVMess:
		return NewVMess(ctx, router, logger, tag, options.VMessOptions)
	case C.TypeNaive:
		return NewNaive(ctx, router, logger, tag, options.NaiveOptions)
	case C.TypeVLESS:
		return NewVLESS(ctx, router, logger, tag, options.VLESSOptions)
	case C.TypeTUIC:
		return NewTUIC(ctx, router, logger, tag, options.TUICOptions)
	default:
		return nil, E.New("unknown inbound type: ", options.Type)
	}
}
