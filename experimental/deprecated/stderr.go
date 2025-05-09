package deprecated

import (
	"os"
	"strconv"

	"github.com/konglong147/securefile/local/sing/common/logger"
)

type stderrManager struct {
	logger   logger.Logger
	reported map[string]bool
}

func NewStderrManager(logger logger.Logger) Manager {
	return &stderrManager{
		logger:   logger,
		reported: make(map[string]bool),
	}
}

func (f *stderrManager) ReportDeprecated(feature Note) {
	if f.reported[feature.Name] {
		return
	}
	f.reported[feature.Name] = true
	if !feature.Impending() {
		f.logger.Warn(feature.MessageWithLink())
		return
	}
	enable, enableErr := strconv.ParseBool(os.Getenv("ENABLE_DEPRECATED_" + feature.EnvName))
	if enableErr == nil && enable {
		f.logger.Warn(feature.MessageWithLink())
		return
	}
	f.logger.Error(feature.MessageWithLink())
	f.logger.Fatal("to continuing using this feature, set ENABLE_DEPRECATED_" + feature.EnvName + "=true")
}
