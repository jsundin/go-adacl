package optional

import (
	"bytes"
	"encoding/json"
)

type Optional[K any] struct {
	value K
	set   bool
}

type serializedOptional[K any] struct {
	Value *K   `json:"v,omitempty"`
	Set   bool `json:"s"`
}

func Of[K any](value K) Optional[K] {
	return Optional[K]{
		value: value,
		set:   true,
	}
}

func Empty[K any]() Optional[K] {
	return Optional[K]{
		set: false,
	}
}

func (o *Optional[K]) Present() bool {
	return o.set
}

func (o *Optional[K]) Get() K {
	if !o.set {
		panic("optional has not been set prior to get call")
	}
	return o.value
}

func (o *Optional[K]) OrElse(defaultValue K) K {
	if o.set {
		return o.value
	}
	return defaultValue
}

func (o *Optional[K]) IfPresent(consumer func(value K)) {
	if o.set {
		consumer(o.value)
	}
}

func (o *Optional[K]) NotPresent(consumer func()) {
	if !o.set {
		consumer()
	}
}

func (o *Optional[K]) MarshalJSON() ([]byte, error) {
	if !o.set {
		return []byte("null"), nil
	}

	return json.Marshal(&o.value)
}

func (o *Optional[K]) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		o.set = false
		return nil
	}

	o.set = true
	if err := json.NewDecoder(bytes.NewReader(data)).Decode(&o.value); err != nil {
		return err
	}
	return nil
}
