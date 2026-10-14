// Package sample exercises the shapes a regex-based reader loses.
package sample

import (
	"fmt"
	"net/http"

	cab "example.com/x/cabinet"
	"example.com/x/lib/v2"
	"gopkg.in/yaml.v3"
)

// Grouped constants.
const (
	// Alpha is the first.
	Alpha = 1
	Beta  = 2
)

var (
	Gamma = 3
	_     = 4
)

const Solo = "x" // single-line, ungrouped

// Store is an interface with an embedded one.
type Store interface {
	fmt.Stringer
	Get(key string) (string, error)
	Put(key, val string) error
	hidden()
}

// Box is a generic container.
type Box[T any] struct {
	Item T
	Cab  *cab.Cabinet
}

type Alias = http.Client

type Number int

// NoopSink has an unnamed receiver.
type NoopSink struct{}

func (NoopSink) RecordTrace(x int) {}

// Put stores a value (generic receiver).
func (b *Box[T]) Put(v T) {
	b.Item = v
}

// Handle holds a "//" inside strings and a local type.
func Handle(c *cab.Cabinet, r *http.Request) error {
	u := "http://example.com/x"
	raw := `{"target":"http://127.0.0.1/x"}`
	type local struct{ A int }
	_ = local{}
	_ = u + raw
	c.Set("k")
	var cl http.Client
	cl.Do(r)
	s := &Box[int]{}
	s.Put(1)
	yaml.Unmarshal(nil, nil)
	lib.Run()
	fmt.Println("x")
	return nil
}

// Shadow declares a local variable that hides an import.
func Shadow() {
	cab := struct{ Cabinet int }{}
	_ = cab.Cabinet
}

func Generic[T any](v T) T {
	return Identity[T](v)
}

func Identity[T any](v T) T { return v }
