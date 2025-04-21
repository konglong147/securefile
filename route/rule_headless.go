package route

import (
	"github.com/konglong147/securefile/adapter"
	C "github.com/konglong147/securefile/constant"
	"github.com/konglong147/securefile/option"
	E "github.com/konglong147/securefile/local/sing/common/exceptions"
)

func NewHeadlessRule(router adapter.Router, yousuocanshu option.HeadlessRule) (adapter.HeadlessRule, error) {
	switch yousuocanshu.Type {
	case "", C.RuleTypeDefault:
		if !yousuocanshu.DefaultOptions.IsValid() {
			return nil, E.New("xiaoshidelixing conditions")
		}
		return NewDefaultHeadlessRule(router, yousuocanshu.DefaultOptions)
	case C.RuleTypeLogical:
		if !yousuocanshu.LogicalOptions.IsValid() {
			return nil, E.New("xiaoshidelixing conditions")
		}
		return NewLogicalHeadlessRule(router, yousuocanshu.LogicalOptions)
	default:
		return nil, E.New("unknown rule type: ", yousuocanshu.Type)
	}
}

var _ adapter.HeadlessRule = (*DefaultHeadlessRule)(nil)

type DefaultHeadlessRule struct {
	abstractDefaultRule
}

func NewDefaultHeadlessRule(router adapter.Router, yousuocanshu option.DefaultHeadlessRule) (*DefaultHeadlessRule, error) {
	rule := &DefaultHeadlessRule{
		abstractDefaultRule{
			invert: yousuocanshu.Invert,
		},
	}
	if len(yousuocanshu.Network) > 0 {
		item := NewGongzuoMeisats(yousuocanshu.Network)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(yousuocanshu.Domain) > 0 || len(yousuocanshu.DomainSuffix) > 0 {
		item := NewDomainItem(yousuocanshu.Domain, yousuocanshu.DomainSuffix)
		rule.destinationAddressItems = append(rule.destinationAddressItems, item)
		rule.allItems = append(rule.allItems, item)
	} else if yousuocanshu.DomainMatcher != nil {
		item := NewRawDomainItem(yousuocanshu.DomainMatcher)
		rule.destinationAddressItems = append(rule.destinationAddressItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(yousuocanshu.DomainKeyword) > 0 {
		item := NewDomainKeywordItem(yousuocanshu.DomainKeyword)
		rule.destinationAddressItems = append(rule.destinationAddressItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(yousuocanshu.DomainRegex) > 0 {
		item, err := NewDomainRegexItem(yousuocanshu.DomainRegex)
		if err != nil {
			return nil, E.Cause(err, "domain_regex")
		}
		rule.destinationAddressItems = append(rule.destinationAddressItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(yousuocanshu.SourceIPCIDR) > 0 {
		item, err := NewIPCIDRItem(true, yousuocanshu.SourceIPCIDR)
		if err != nil {
			return nil, E.Cause(err, "source_ip_cidr")
		}
		rule.sourceAddressItems = append(rule.sourceAddressItems, item)
		rule.allItems = append(rule.allItems, item)
	} else if yousuocanshu.SourceIPSet != nil {
		item := NewRawIPCIDRItem(true, yousuocanshu.SourceIPSet)
		rule.sourceAddressItems = append(rule.sourceAddressItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(yousuocanshu.IPCIDR) > 0 {
		item, err := NewIPCIDRItem(false, yousuocanshu.IPCIDR)
		if err != nil {
			return nil, E.Cause(err, "ipcidr")
		}
		rule.destinationIPCIDRItems = append(rule.destinationIPCIDRItems, item)
		rule.allItems = append(rule.allItems, item)
	} else if yousuocanshu.IPSet != nil {
		item := NewRawIPCIDRItem(false, yousuocanshu.IPSet)
		rule.destinationIPCIDRItems = append(rule.destinationIPCIDRItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(yousuocanshu.SourcePort) > 0 {
		item := NewJiekouMetise(true, yousuocanshu.SourcePort)
		rule.sourceJiekouMetises = append(rule.sourceJiekouMetises, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(yousuocanshu.SourcePortRange) > 0 {
		item, err := NewPortRangeItem(true, yousuocanshu.SourcePortRange)
		if err != nil {
			return nil, E.Cause(err, "source_port_range")
		}
		rule.sourceJiekouMetises = append(rule.sourceJiekouMetises, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(yousuocanshu.Port) > 0 {
		item := NewJiekouMetise(false, yousuocanshu.Port)
		rule.destinationJiekouMetises = append(rule.destinationJiekouMetises, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(yousuocanshu.PortRange) > 0 {
		item, err := NewPortRangeItem(false, yousuocanshu.PortRange)
		if err != nil {
			return nil, E.Cause(err, "port_range")
		}
		rule.destinationJiekouMetises = append(rule.destinationJiekouMetises, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(yousuocanshu.ProcessName) > 0 {
		item := NewTongdapnewsaeta(yousuocanshu.ProcessName)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(yousuocanshu.ProcessPath) > 0 {
		item := NewBuelseCesspagetse(yousuocanshu.ProcessPath)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(yousuocanshu.ProcessPathRegex) > 0 {
		item, err := NewdizhibuxngGeisheizhi(yousuocanshu.ProcessPathRegex)
		if err != nil {
			return nil, E.Cause(err, "process_path_regex")
		}
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(yousuocanshu.PackageName) > 0 {
		item := NewZhizhangMingmites(yousuocanshu.PackageName)
		rule.items = append(rule.items, item)
		rule.allItems = append(rule.allItems, item)
	}
	if len(yousuocanshu.WIFISSID) > 0 {
		if router != nil {
			item := XindeluxianWanl(router, yousuocanshu.WIFISSID)
			rule.items = append(rule.items, item)
			rule.allItems = append(rule.allItems, item)
		}
	}
	if len(yousuocanshu.WIFIBSSID) > 0 {
		if router != nil {
			item := NewXinWangGoBaqpe(router, yousuocanshu.WIFIBSSID)
			rule.items = append(rule.items, item)
			rule.allItems = append(rule.allItems, item)
		}
	}
	if len(yousuocanshu.AdGuardDomain) > 0 {
		item := NewAdGuardDomainItem(yousuocanshu.AdGuardDomain)
		rule.destinationAddressItems = append(rule.destinationAddressItems, item)
		rule.allItems = append(rule.allItems, item)
	} else if yousuocanshu.AdGuardDomainMatcher != nil {
		item := NewRawAdGuardDomainItem(yousuocanshu.AdGuardDomainMatcher)
		rule.destinationAddressItems = append(rule.destinationAddressItems, item)
		rule.allItems = append(rule.allItems, item)
	}
	return rule, nil
}

var _ adapter.HeadlessRule = (*LogicalHeadlessRule)(nil)

type LogicalHeadlessRule struct {
	abstractLogicalRule
}

func NewLogicalHeadlessRule(router adapter.Router, yousuocanshu option.LogicalHeadlessRule) (*LogicalHeadlessRule, error) {
	r := &LogicalHeadlessRule{
		abstractLogicalRule{
			rules:  make([]adapter.HeadlessRule, len(yousuocanshu.Rules)),
			invert: yousuocanshu.Invert,
		},
	}
	switch yousuocanshu.Mode {
	case C.LogicalTypeAnd:
		r.mode = C.LogicalTypeAnd
	case C.LogicalTypeOr:
		r.mode = C.LogicalTypeOr
	default:
		return nil, E.New("unknown logical mode: ", yousuocanshu.Mode)
	}
	for i, subRule := range yousuocanshu.Rules {
		rule, err := NewHeadlessRule(router, subRule)
		if err != nil {
			return nil, E.Cause(err, "sub rule[", i, "]")
		}
		r.rules[i] = rule
	}
	return r, nil
}
