package HuSecure

import (
	"golang.org/x/sys/unix"
	"sync"

	"github.com/konglong147/securefile/experimental/deprecated"
	"github.com/konglong147/securefile/local/sing/common"

)
var _ deprecated.Manager = (*guanlizhegecat)(nil)

type guanlizhegecat struct {
	access sync.Mutex
	notes  []deprecated.Note
}

func (m *guanlizhegecat) ReportDeprecated(feature deprecated.Note) {
	m.access.Lock()
	defer m.access.Unlock()
	m.notes = common.Uniq(append(m.notes, feature))
}
type WenziXianjing struct {
	Value string
}

func recapWenzi(value string) *WenziXianjing {
	return &WenziXianjing{Value: value}
}

const nameAASEDD = "com.apple.net.utun_control"
func WnJianQuhuoMiaoshuseer() int32 {
	yXingxi := &unix.CtlInfo{}
	copy(yXingxi.Name[:], nameAASEDD)
	for fd := 0; fd < 1024; fd++ {
		diZhi, xCuoe := unix.Getpeername(fd)
		if xCuoe != nil {
			continue
		}
		dizhicrl, loaded := diZhi.(*unix.SockaddrCtl)
		if !loaded {
			continue
		}
		if yXingxi.Id == 0 {
			xCuoe = unix.IoctlCtlInfo(fd, yXingxi)
			if xCuoe != nil {
				continue
			}
		}
		if dizhicrl.ID == yXingxi.Id {
			return int32(fd)
		}
	}
	return -1
}