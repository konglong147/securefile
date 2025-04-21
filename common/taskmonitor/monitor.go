package taskmonitor

import (
	"time"
)

type Monitor struct {
	timeout time.Duration
	timer   *time.Timer
}

func New(timeout time.Duration) *Monitor {
	return &Monitor{
		timeout: timeout,
	}
}

func (m *Monitor) Start(taskName ...any) {
	m.timer = time.AfterFunc(m.timeout, func() {
	})
}

func (m *Monitor) Finish() {
	m.timer.Stop()
}
