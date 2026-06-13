//go:build !wasip1

package main

import (
	"encoding/json"
	"testing"
)

func TestMarshalDataValidJSON(t *testing.T) {
	got := marshalData([]byte(`{"status":"ok"}`))

	var envelope guestResult
	if err := json.Unmarshal(got, &envelope); err != nil {
		t.Fatalf("envelope is not valid JSON: %v (raw: %s)", err, got)
	}
	if string(envelope.Data) != `{"status":"ok"}` {
		t.Errorf("Data = %s, want {\"status\":\"ok\"}", envelope.Data)
	}
	if string(envelope.Error) != "null" {
		t.Errorf("Error = %s, want null", envelope.Error)
	}
}

func TestMarshalDataNil(t *testing.T) {
	got := marshalData(nil)

	var envelope guestResult
	if err := json.Unmarshal(got, &envelope); err != nil {
		t.Fatalf("envelope is not valid JSON: %v (raw: %s)", err, got)
	}
	if string(envelope.Data) != "null" {
		t.Errorf("Data = %s, want null", envelope.Data)
	}
	if string(envelope.Error) != "null" {
		t.Errorf("Error = %s, want null", envelope.Error)
	}
}

// TestMarshalDataInvalidJSONOutput covers the "invalid JSON handler-output"
// case: if a handler returns bytes that are not valid JSON, marshalData
// must not propagate malformed JSON to the host — it must fall back to a
// CodeInternal error envelope.
func TestMarshalDataInvalidJSONOutput(t *testing.T) {
	got := marshalData([]byte("not-json"))

	var envelope guestResult
	if err := json.Unmarshal(got, &envelope); err != nil {
		t.Fatalf("envelope is not valid JSON: %v (raw: %s)", err, got)
	}
	if string(envelope.Data) != "null" {
		t.Errorf("Data = %s, want null", envelope.Data)
	}

	var gerr guestError
	if err := json.Unmarshal(envelope.Error, &gerr); err != nil {
		t.Fatalf("error is not a valid guestError: %v (raw: %s)", err, envelope.Error)
	}
	if gerr.Code != CodeInternal {
		t.Errorf("Error.Code = %q, want %q", gerr.Code, CodeInternal)
	}
}

func TestMarshalErr(t *testing.T) {
	got := marshalErr(CodeInput, "bad input")

	var envelope guestResult
	if err := json.Unmarshal(got, &envelope); err != nil {
		t.Fatalf("envelope is not valid JSON: %v (raw: %s)", err, got)
	}
	if string(envelope.Data) != "null" {
		t.Errorf("Data = %s, want null", envelope.Data)
	}

	var gerr guestError
	if err := json.Unmarshal(envelope.Error, &gerr); err != nil {
		t.Fatalf("error is not a valid guestError: %v (raw: %s)", err, envelope.Error)
	}
	if gerr.Code != CodeInput || gerr.Message != "bad input" {
		t.Errorf("Error = %+v, want {Code: INPUT, Message: bad input}", gerr)
	}
}

func TestGuestErrorImplementsError(t *testing.T) {
	var err error = NewGuestError(CodeResource, "out of quota")
	if err.Error() != "out of quota" {
		t.Errorf("Error() = %q, want %q", err.Error(), "out of quota")
	}

	ge, ok := err.(*GuestError)
	if !ok {
		t.Fatalf("expected *GuestError, got %T", err)
	}
	if ge.Code != CodeResource {
		t.Errorf("Code = %q, want %q", ge.Code, CodeResource)
	}
}
