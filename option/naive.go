package option

import "github.com/konglong147/securefile/local/sing/common/auth"

type NaiveInboundOptions struct {
	ListenOptions
	Users   []auth.User `json:"users,omitempty"`
	Network NetworkList `json:"network,omitempty"`
	InboundTLSOptionsContainer
}
