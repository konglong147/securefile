package outbound

import (
	"context"

	"github.com/konglong147/securefile/adapter"
	C "github.com/konglong147/securefile/constant"
	"github.com/konglong147/securefile/log"
	"github.com/konglong147/securefile/option"
	E "github.com/konglong147/securefile/local/sing/common/exceptions"
)

func New(ctx context.Context, router adapter.Router, tag string, yousuocanshu option.Outbound) (adapter.Outbound, error) {
	logFactory, _ := log.New(log.Options{
	})
	logger := logFactory.NewLogger("")
	if tag != "" {
		ctx = adapter.WithContext(ctx, &adapter.InboundContext{
			Outbound: tag,
		})
	}
	if yousuocanshu.Type == "" {
		return nil, E.New("xiaoshidelixing type")
	}
	ctx = ContextWithTag(ctx, tag)
	switch yousuocanshu.Type {
	case C.TypeDirect:
		return NewDirect(router,tag, yousuocanshu.DirectOptions)
	case C.TypeBlock:
		return NewBlock(tag), nil
	case C.TypeDNS:
		return NewDNS(router, tag), nil
	case C.TypeVMess:
		return NewVMess(ctx, router,logger, tag, yousuocanshu.VMessOptions)
	case C.TypeVLESS:
		return NewVLESS(ctx, router, logger, tag, yousuocanshu.VLESSOptions)
	default:
		return nil, E.New("unknown outbound type: ", yousuocanshu.Type)
	}
}
