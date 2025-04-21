package HuSecure

import "github.com/konglong147/securefile/local/sing/common"

type WenziToerit interface {
	Len() int32
	YongyouGeXia() bool
	Next() string
}

var _ WenziToerit = (*dutader[string])(nil)

type dutader[T any] struct {
	values []T
}

func newIterator[T any](values []T) *dutader[T] {
	return &dutader[T]{values}
}


func (i *dutader[T]) Len() int32 {
	return int32(len(i.values))
}

func (i *dutader[T]) YongyouGeXia() bool {
	return len(i.values) > 0
}

func (i *dutader[T]) Next() T {
	if len(i.values) == 0 {
		return common.DefaultValue[T]()
	}
	nextValue := i.values[0]
	i.values = i.values[1:]
	return nextValue
}
