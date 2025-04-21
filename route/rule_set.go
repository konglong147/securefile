package route

import (
	"context"

	"github.com/konglong147/securefile/adapter"
	"github.com/konglong147/securefile/option"
	"github.com/konglong147/securefile/local/sing/common"
	E "github.com/konglong147/securefile/local/sing/common/exceptions"

	"go4.org/netipx"
)

func NewRuleSet(ctx context.Context, router adapter.Router, yousuocanshu option.RuleSet) (adapter.RuleSet, error) {
	return nil, E.New("unknown rule-set type: ", yousuocanshu.Type)
}

func extractIPSetFromRule(rawRule adapter.HeadlessRule) []*netipx.IPSet {
	switch rule := rawRule.(type) {
	case *DefaultHeadlessRule:
		return common.FlatMap(rule.destinationIPCIDRItems, func(rawItem RuleItem) []*netipx.IPSet {
			switch item := rawItem.(type) {
			case *IPCIDRItem:
				return []*netipx.IPSet{item.ipSet}
			default:
				return nil
			}
		})
	case *LogicalHeadlessRule:
		return common.FlatMap(rule.rules, extractIPSetFromRule)
	default:
		panic("unexpected rule type")
	}
}
