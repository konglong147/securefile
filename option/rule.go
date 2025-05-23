package option

import (
	"reflect"

	C "github.com/konglong147/securefile/constant"
	"github.com/konglong147/securefile/local/sing/common"
	E "github.com/konglong147/securefile/local/sing/common/exceptions"
	"github.com/konglong147/securefile/local/sing/common/json"
)

type _Rule struct {
	Type           string      `json:"type,omitempty"`
	DefaultOptions DefaultRule `json:"-"`
	LogicalOptions LogicalRule `json:"-"`
}

type Rule _Rule

func (r Rule) MarshalJSON() ([]byte, error) {
	var v any
	switch r.Type {
	case C.RuleTypeDefault:
		r.Type = ""
		v = r.DefaultOptions
	case C.RuleTypeLogical:
		v = r.LogicalOptions
	default:
		return nil, E.New("unknown rule type: " + r.Type)
	}
	return MarshallObjects((_Rule)(r), v)
}

func (r *Rule) UnmarshalJSON(bytes []byte) error {
	err := json.Unmarshal(bytes, (*_Rule)(r))
	if err != nil {
		return err
	}
	var v any
	switch r.Type {
	case "", C.RuleTypeDefault:
		r.Type = C.RuleTypeDefault
		v = &r.DefaultOptions
	case C.RuleTypeLogical:
		v = &r.LogicalOptions
	default:
		return E.New("unknown rule type: " + r.Type)
	}
	err = UnmarshallExcluded(bytes, (*_Rule)(r), v)
	if err != nil {
		return err
	}
	return nil
}

func (r Rule) IsValid() bool {
	switch r.Type {
	case C.RuleTypeDefault:
		return r.DefaultOptions.IsValid()
	case C.RuleTypeLogical:
		return r.LogicalOptions.IsValid()
	default:
		panic("unknown rule type: " + r.Type)
	}
}

type DefaultRule struct {
	Inbound                  Listable[string] `json:"inbound,omitempty"`
	IPVersion                int              `json:"ip_version,omitempty"`
	Network                  Listable[string] `json:"network,omitempty"`
	AuthUser                 Listable[string] `json:"auth_user,omitempty"`
	Protocol                 Listable[string] `json:"protocol,omitempty"`
	Client                   Listable[string] `json:"client,omitempty"`
	Domain                   Listable[string] `json:"domain,omitempty"`
	DomainSuffix             Listable[string] `json:"domain_suffix,omitempty"`
	DomainKeyword            Listable[string] `json:"domain_keyword,omitempty"`
	DomainRegex              Listable[string] `json:"domain_regex,omitempty"`
	Geosite                  Listable[string] `json:"geosite,omitempty"`
	SourceGeoIP              Listable[string] `json:"source_geoip,omitempty"`
	GeoIP                    Listable[string] `json:"geoip,omitempty"`
	SourceIPCIDR             Listable[string] `json:"source_ip_cidr,omitempty"`
	SourceIPIsPrivate        bool             `json:"source_ip_is_private,omitempty"`
	IPCIDR                   Listable[string] `json:"ip_cidr,omitempty"`
	IPIsPrivate              bool             `json:"ip_is_private,omitempty"`
	SourcePort               Listable[uint16] `json:"source_port,omitempty"`
	SourcePortRange          Listable[string] `json:"source_port_range,omitempty"`
	Port                     Listable[uint16] `json:"port,omitempty"`
	PortRange                Listable[string] `json:"port_range,omitempty"`
	ProcessName              Listable[string] `json:"process_name,omitempty"`
	ProcessPath              Listable[string] `json:"process_path,omitempty"`
	ProcessPathRegex         Listable[string] `json:"process_path_regex,omitempty"`
	PackageName              Listable[string] `json:"package_name,omitempty"`
	User                     Listable[string] `json:"user,omitempty"`
	UserID                   Listable[int32]  `json:"user_id,omitempty"`
	ClashMode                string           `json:"clash_mode,omitempty"`
	WIFISSID                 Listable[string] `json:"wifi_ssid,omitempty"`
	WIFIBSSID                Listable[string] `json:"wifi_bssid,omitempty"`
	RuleSet                  Listable[string] `json:"rule_set,omitempty"`
	RuleSetIPCIDRMatchSource bool             `json:"rule_set_ip_cidr_match_source,omitempty"`
	Invert                   bool             `json:"invert,omitempty"`
	Outbound                 string           `json:"outbound,omitempty"`

	// Deprecated: renamed to rule_set_ip_cidr_match_source
	Deprecated_RulesetIPCIDRMatchSource bool `json:"rule_set_ipcidr_match_source,omitempty"`
}

func (r *DefaultRule) IsValid() bool {
	var defaultValue DefaultRule
	defaultValue.Invert = r.Invert
	defaultValue.Outbound = r.Outbound
	return !reflect.DeepEqual(r, defaultValue)
}

type LogicalRule struct {
	Mode     string `json:"mode"`
	Rules    []Rule `json:"rules,omitempty"`
	Invert   bool   `json:"invert,omitempty"`
	Outbound string `json:"outbound,omitempty"`
}

func (r LogicalRule) IsValid() bool {
	return len(r.Rules) > 0 && common.All(r.Rules, Rule.IsValid)
}
