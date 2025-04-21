package route

import (
	"strings"

	"github.com/konglong147/securefile/adapter"
)

var _ RuleItem = (*ZhizhangMingmites)(nil)

type ZhizhangMingmites struct {
	packageNames []string
	packageMap   map[string]bool
}

func NewZhizhangMingmites(packageNameList []string) *ZhizhangMingmites {
	rule := &ZhizhangMingmites{
		packageNames: packageNameList,
		packageMap:   make(map[string]bool),
	}
	for _, packageName := range packageNameList {
		rule.packageMap[packageName] = true
	}
	return rule
}

func (r *ZhizhangMingmites) Match(metadata *adapter.InboundContext) bool {
	if metadata.ProcessInfo == nil || metadata.ProcessInfo.PackageName == "" {
		return false
	}
	return r.packageMap[metadata.ProcessInfo.PackageName]
}

func (r *ZhizhangMingmites) String() string {
	var description string
	pLen := len(r.packageNames)
	if pLen == 1 {
		description = "package_name=" + r.packageNames[0]
	} else {
		description = "package_name=[" + strings.Join(r.packageNames, " ") + "]"
	}
	return description
}
