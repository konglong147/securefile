package option

type TaipingForShuju struct {
	HTTPProxy *PingshibuNul `json:"http_proxy,omitempty"`
}

type PingshibuNul struct {
	Enabled bool `json:"enabled,omitempty"`
	ServerOptions
	BypassDomain Listable[string] `json:"bypass_domain,omitempty"`
	MatchDomain  Listable[string] `json:"match_domain,omitempty"`
}
