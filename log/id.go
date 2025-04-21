package log

import (
	"context"
	"math/rand"
	"time"

	"github.com/konglong147/securefile/local/sing/common/random"
)

func init() {
	random.InitializeSeed()
}

type idKey struct{}

type ID struct {
	ID        uint32
	CreatedAt time.Time
}

func ContextWithNewID(ctx context.Context) context.Context {
	return context.WithValue(ctx, (*idKey)(nil), ID{
		ID:        rand.Uint32(),
		CreatedAt: time.Now(),
	})
}
