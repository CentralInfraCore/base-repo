// Package canonicaljson produces deterministic, sorted-key JSON output so the
// same logical document always hashes to the same digest across languages
// and services.
//
// Vendored verbatim from CentralInfraCore/CIC-Relay (pkg/canonicaljson), same
// author/copyright — kept identical rather than reimplemented, so anything
// hashed with this copy matches whatever CIC-Relay itself computes. If the
// source changes, re-vendor rather than fork. tools/canonicalize (this
// template's CLI wrapper) depends on it; CentralInfraCore/cic-countersign
// carries its own separately-vendored copy of the same file under its own
// module path.
package canonicaljson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

// ToJSONFunc is the type for the ToJSON function, allowing it to be mocked.
type ToJSONFunc func(v any) ([]byte, error)

// ToJSONImpl is the actual implementation of ToJSON that can be swapped for testing.
var ToJSONImpl ToJSONFunc = ToJSONOriginal

// ToJSONOriginal is the original implementation of ToJSON.
func ToJSONOriginal(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := writeCanonicalJSON(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ToJSON marshals a Go value into a canonical JSON string.
// It ensures that map keys are sorted alphabetically for deterministic output.
func ToJSON(v any) ([]byte, error) {
	return ToJSONImpl(v)
}

// SetToJSONMock sets the mock function for ToJSON.
// Pass nil to restore the original implementation.
func SetToJSONMock(mock ToJSONFunc) {
	if mock == nil {
		ToJSONImpl = ToJSONOriginal
	} else {
		ToJSONImpl = mock
	}
}

func writeCanonicalJSON(w io.Writer, v any) error {
	switch vv := v.(type) {
	case nil:
		_, err := w.Write([]byte("null"))
		return err
	case bool:
		_, err := w.Write([]byte(fmt.Sprintf("%t", vv)))
		return err
	case float64:
		// Use json.Marshal for correct float formatting (e.g., scientific notation)
		return writeJSONString(w, vv)
	case string:
		return writeJSONString(w, vv)
	case []any:
		return writeJSONArray(w, vv)
	case map[string]any:
		return writeJSONMap(w, vv)
	default:
		// For other types (like structs or other numeric types), marshal them first.
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}

		// If the result is a JSON object, unmarshal it into a map to sort the keys.
		// This handles structs correctly.
		if len(b) > 0 && b[0] == '{' {
			var m map[string]any
			if err := json.Unmarshal(b, &m); err != nil {
				// This should be unlikely if json.Marshal produced valid JSON.
				return fmt.Errorf("failed to re-unmarshal for canonicalization: %w", err)
			}
			return writeJSONMap(w, m)
		}

		// Otherwise, it's a primitive (number, string) or an array, which is fine.
		_, err = w.Write(b)
		return err
	}
}

func writeJSONString(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func writeJSONArray(w io.Writer, arr []any) error {
	if _, err := w.Write([]byte("[")); err != nil {
		return err
	}
	for i, item := range arr {
		if i > 0 {
			if _, err := w.Write([]byte(",")); err != nil {
				return err
			}
		}
		if err := writeCanonicalJSON(w, item); err != nil {
			return err
		}
	}
	_, err := w.Write([]byte("]"))
	return err
}

func writeJSONMap(w io.Writer, m map[string]any) error {
	if _, err := w.Write([]byte("{")); err != nil {
		return err
	}

	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for i, k := range keys {
		if i > 0 {
			if _, err := w.Write([]byte(",")); err != nil {
				return err
			}
		}
		if err := writeJSONString(w, k); err != nil {
			return err
		}
		if _, err := w.Write([]byte(":")); err != nil {
			return err
		}
		if err := writeCanonicalJSON(w, m[k]); err != nil {
			return err
		}
	}

	_, err := w.Write([]byte("}"))
	return err
}
