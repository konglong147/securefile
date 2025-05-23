package json

import (
	"bytes"
	"errors"
	"strings"

	"github.com/konglong147/securefile/local/sing/common"
	E "github.com/konglong147/securefile/local/sing/common/exceptions"
)

func UnmarshalExtended[T any](content []byte) (T, error) {
	decoder := NewDecoder(NewCommentFilter(bytes.NewReader(content)))
	var value T
	err := decoder.Decode(&value)
	if err == nil {
		return value, err
	}
	var syntaxError *SyntaxError
	if errors.As(err, &syntaxError) {
		prefix := string(content[:syntaxError.Offset])
		row := strings.Count(prefix, "\n") + 1
		column := len(prefix) - strings.LastIndex(prefix, "\n") - 1
		return common.DefaultValue[T](), E.Extend(syntaxError, "row ", row, ", column ", column)
	}
	return common.DefaultValue[T](), err
}
