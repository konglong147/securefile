//go:build !with_acme

package tls

import (
	"context"
	"crypto/tls"

	"github.com/konglong147/securefile/adapter"
	"github.com/konglong147/securefile/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func startACME(ctx context.Context, options option.InboundACMEOptions) (*tls.Config, adapter.Service, error) {
	return nil, nil, E.New(`ACME is not included in this build, rebuild with -tags with_acme`)
}
