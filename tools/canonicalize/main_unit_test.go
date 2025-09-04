package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func Test_writeJSONString_Simple(t *testing.T) {
	var b bytes.Buffer
	writeJSONString(&b, "hello")
	got := b.String()
	if got != `"hello"` {
		t.Fatalf("want %q, got %q", `"hello"`, got)
	}
}

func Test_writeCanonicalJSON_MapOrderStable(t *testing.T) {
	m := map[string]any{"b": 2, "a": 1}
	var b bytes.Buffer
	writeCanonicalJSON(&b, m)
	if got := b.String(); got != `{"a":1,"b":2}` {
		t.Fatalf("want %q, got %q", `{"a":1,"b":2}`, got)
	}
}

func Test_writeCanonicalJSON_ArrayMix(t *testing.T) {
	v := []any{"x", true, nil, json.Number("123")}
	var b bytes.Buffer
	writeCanonicalJSON(&b, v)
	if got := b.String(); got != `["x",true,null,123]` {
		t.Fatalf("want %q, got %q", `["x",true,null,123]`, got)
	}
}

func Test_writeCanonicalJSON_Nested(t *testing.T) {
	v := map[string]any{
		"list": []any{map[string]any{"z": 1, "a": 2}, "ok"},
		"m":    map[string]any{"k":"v"},
	}
	var b bytes.Buffer
	writeCanonicalJSON(&b, v)
	got := b.String()
	// kulcsoknak lexikografikus sorrendben kell lenniük a belső mapokban is
	if !strings.Contains(got, `{"a":2,"z":1}`) {
		t.Fatalf("nested map not canonical: %q", got)
	}
}
