package main

import (
	"testing"

	"centralrelay/pkg/canonicaljson"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCanonicalJSONOutput(t *testing.T) {
	testCases := []struct {
		name     string
		input    any
		wantJSON string
	}{
		{
			name:     "simple map",
			input:    map[string]any{"b": 2, "a": 1},
			wantJSON: `{"a":1,"b":2}`,
		},
		{
			name:     "nested map",
			input:    map[string]any{"c": 3, "a": map[string]any{"z": 26, "y": 25}},
			wantJSON: `{"a":{"y":25,"z":26},"c":3}`,
		},
		{
			name:     "array of maps",
			input:    []any{map[string]any{"b": 2}, map[string]any{"a": 1}},
			wantJSON: `[{"b":2},{"a":1}]`, // Array order is preserved
		},
		{
			name:     "complex structure",
			input:    map[string]any{"p": true, "n": nil, "s": "string", "arr": []any{"x", "y"}},
			wantJSON: `{"arr":["x","y"],"n":null,"p":true,"s":"string"}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gotBytes, err := canonicaljson.ToJSON(tc.input)
			require.NoError(t, err)
			assert.JSONEq(t, tc.wantJSON, string(gotBytes), "The canonical JSON output should match the expected string")
		})
	}
}
