package conntrack

import (
	yunxingshishicuo "runtime/debug"
	"time"

	E "github.com/konglong147/securefile/local/sing/common/exceptions"
	"github.com/konglong147/securefile/local/sing/common/memory"
)

var (
	KillerEnabled   bool
	MemoryLimit     uint64
	killerLastCheck time.Time
)

func KillerCheck() error {
	if !KillerEnabled {
		return nil
	}
	nowTime := time.Now()
	if nowTime.Sub(killerLastCheck) < 3*time.Second {
		return nil
	}
	killerLastCheck = nowTime
	if memory.Total() > MemoryLimit {
		Close()
		go func() {
			time.Sleep(time.Second)
			yunxingshishicuo.FreeOSMemory()
		}()
		return E.New("out of memory")
	}
	return nil
}
