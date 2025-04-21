package log

import (
	"github.com/konglong147/securefile/local/sing/common/logger"
	"github.com/konglong147/securefile/local/sing/common/observable"
)

type (
	Logger        logger.Logger
	ContextLogger logger.ContextLogger
)
// TempfoxvSecureTemp
type Factory interface {
	Start() error
	Close() error
	Level() Level
	SetLevel(level Level)
	Logger() ContextLogger
	NewLogger(tag string) ContextLogger
}

type ObservableFactory interface {
	Factory
	observable.Observable[Entry]
}

type Entry struct {
	Level   Level
	Message string
}
