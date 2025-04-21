package log

import (
	"context"
	"io"
	"time"
	"github.com/konglong147/securefile/option"
)

type Options struct {
	Context        context.Context
	Options        option.LogOptions
	Observable     bool
	DefaultWriter  io.Writer
	BaseTime       time.Time
}

func New(yousuocanshu Options) (Factory, error) {
	
	factory := NewDefaultFactory(
	
	)
	return factory, nil
}
