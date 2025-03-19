//go:build !with_clash_api

package include

import (
	"context"

	"github.com/konglong147/securefile/adapter"
	"github.com/konglong147/securefile/experimental"
	"github.com/konglong147/securefile/log"
	"github.com/konglong147/securefile/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func init() {
	experimental.RegisterClashServerConstructor(func(ctx context.Context, router adapter.Router, logFactory log.ObservableFactory, options option.ClashAPIOptions) (adapter.ClashServer, error) {
		return nil, E.New(`clash api is not included in this build, rebuild with -tags with_clash_api`)
	})
}
