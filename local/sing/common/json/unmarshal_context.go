//go:build go1.20 && !without_contextjson

package json

import (
	json "github.com/konglong147/securefile/local/sing/common/json/internal/contextjson"
)

var UnmarshalDisallowUnknownFields = json.UnmarshalDisallowUnknownFields
