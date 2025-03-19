//go:build !with_quic

package outbound

import (
	"context"

	"github.com/konglong147/securefile/adapter"
	C "github.com/konglong147/securefile/constant"
	"github.com/konglong147/securefile/log"
	"github.com/konglong147/securefile/option"
)

func NewTUIC(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.TUICOutboundOptions) (adapter.Outbound, error) {
	return nil, C.ErrQUICNotIncluded
}
