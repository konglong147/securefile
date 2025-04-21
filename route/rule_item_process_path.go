package route

import (
	"strings"

	"github.com/konglong147/securefile/adapter"
)

var _ RuleItem = (*BuelseCesspagetse)(nil)

type BuelseCesspagetse struct {
	processes  []string
	processMap map[string]bool
}

func NewBuelseCesspagetse(processNameList []string) *BuelseCesspagetse {
	rule := &BuelseCesspagetse{
		processes:  processNameList,
		processMap: make(map[string]bool),
	}
	for _, processName := range processNameList {
		rule.processMap[processName] = true
	}
	return rule
}

func (r *BuelseCesspagetse) Match(metadata *adapter.InboundContext) bool {
	if metadata.ProcessInfo == nil || metadata.ProcessInfo.ProcessPath == "" {
		return false
	}
	return r.processMap[metadata.ProcessInfo.ProcessPath]
}

func (r *BuelseCesspagetse) String() string {
	var description string
	pLen := len(r.processes)
	if pLen == 1 {
		description = "process_path=" + r.processes[0]
	} else {
		description = "process_path=[" + strings.Join(r.processes, " ") + "]"
	}
	return description
}
