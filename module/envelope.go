// Package main — envelope.go holds the {data, error} wire-format types and
// the typed handler-error contract (KB c689). It has no build tag so that it
// is shared by the TinyGo/wasip1 guest build (abi.go, handlers.go) and the
// host-side `go test` of the dispatcher logic (envelope_test.go).
package main

import "encoding/json"

// guestResult mirrors the host's GuestResult (cicwasm.go:346): {data, error}.
type guestResult struct {
	Data  json.RawMessage `json:"data"`
	Error json.RawMessage `json:"error"`
}

// guestError mirrors the error-codes contract (KB c689): INPUT|RUNTIME|INTERNAL|RESOURCE|TIMEOUT.
type guestError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Error codes (KB c689). Use these with NewGuestError from handlers.go to
// control the {error.code} the host sees; a plain (untyped) error defaults
// to CodeRuntime in the dispatcher (abi.go: Call).
const (
	CodeInput    = "INPUT"
	CodeRuntime  = "RUNTIME"
	CodeInternal = "INTERNAL"
	CodeResource = "RESOURCE"
	CodeTimeout  = "TIMEOUT"
)

// GuestError is a typed handler error carrying one of the iSDK error codes
// above. Returning *GuestError from a handler (handlers.go) lets the
// dispatcher (abi.go: Call) report that exact code to the host instead of
// the CodeRuntime default.
type GuestError struct {
	Code    string
	Message string
}

func (e *GuestError) Error() string { return e.Message }

// NewGuestError builds a *GuestError for the given code/message.
func NewGuestError(code, message string) *GuestError {
	return &GuestError{Code: code, Message: message}
}

// marshalData wraps a handler's raw JSON payload into the {data, error}
// envelope. If the handler returned bytes that are not valid JSON, this
// produces a CodeInternal error envelope instead of propagating malformed
// JSON to the host.
func marshalData(data []byte) []byte {
	if data == nil {
		data = []byte("null")
	}
	if !json.Valid(data) {
		return marshalErr(CodeInternal, "handler returned invalid JSON output")
	}
	b, err := json.Marshal(guestResult{Data: json.RawMessage(data), Error: json.RawMessage("null")})
	if err != nil {
		return marshalErr(CodeInternal, err.Error())
	}
	return b
}

// marshalErr wraps an error code/message into the {data, error} envelope.
// Error codes ∈ INPUT|RUNTIME|INTERNAL|RESOURCE|TIMEOUT (KB c689).
func marshalErr(code, message string) []byte {
	errBytes, _ := json.Marshal(guestError{Code: code, Message: message})
	b, err := json.Marshal(guestResult{Data: json.RawMessage("null"), Error: json.RawMessage(errBytes)})
	if err != nil {
		// last-resort fallback — must never fail to produce valid JSON
		return []byte(`{"data":null,"error":{"code":"INTERNAL","message":"marshal failure"}}`)
	}
	return b
}
