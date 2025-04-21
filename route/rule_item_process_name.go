package route

import (
	"path/filepath"
	"strings"

	"github.com/konglong147/securefile/adapter"
)

var _ RuleItem = (*Tongdapnewsaeta)(nil)

type Tongdapnewsaeta struct {
	processes  []string
	processMap map[string]bool
}

func NewTongdapnewsaeta(processNameList []string) *Tongdapnewsaeta {
	rule := &Tongdapnewsaeta{
		processes:  processNameList,
		processMap: make(map[string]bool),
	}
	for _, processName := range processNameList {
		rule.processMap[processName] = true
	}
	return rule
}

func (r *Tongdapnewsaeta) Match(metadata *adapter.InboundContext) bool {
	if metadata.ProcessInfo == nil || metadata.ProcessInfo.ProcessPath == "" {
		return false
	}
	return r.processMap[filepath.Base(metadata.ProcessInfo.ProcessPath)]
}

func (r *Tongdapnewsaeta) String() string {
	var description string
	pLen := len(r.processes)
	if pLen == 1 {
		description = "process_name=" + r.processes[0]
	} else {
		description = "process_name=[" + strings.Join(r.processes, " ") + "]"
	}
	return description
}
