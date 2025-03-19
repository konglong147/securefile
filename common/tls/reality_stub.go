//go:build !with_reality_server

package tls

import (
	"context"

	"github.com/konglong147/securefile/log"
	"github.com/konglong147/securefile/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func NewRealityServer(ctx context.Context, logger log.Logger, options option.InboundTLSOptions) (ServerConfig, error) {
	return nil, E.New(`reality server is not included in this build, rebuild with -tags with_reality_server`)
}
