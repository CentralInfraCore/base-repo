//go:build wasip1

package main

import "encoding/json"

// Domain handlers — implement your module here. Each returns (dataJSON, error).
// Signatures match the iSDK contract (KB c689): (auth_context_json, data_json) -> (data_json, error).
// v1 is synchronous, deterministic, WASI-off (no external I/O).
//
// Return a plain error for an unexpected/internal failure (the dispatcher in
// abi.go reports it as CodeRuntime), or *GuestError via NewGuestError(code, msg)
// (envelope.go) to report one of CodeInput|CodeRuntime|CodeInternal|CodeResource|CodeTimeout
// explicitly — see Get below for an example of CodeInput on bad caller data.

// Init handles the "init" op — module bring-up / configuration.
func Init(auth, data []byte) ([]byte, error) {
	// TODO: bring-up/config
	return nil, nil
}

// Process handles the "process" op — the module's main operation.
func Process(auth, data []byte) ([]byte, error) {
	// TODO: main op
	return nil, nil
}

// Get handles the "get" op — an idempotent read.
func Get(auth, data []byte) ([]byte, error) {
	if len(data) > 0 && !json.Valid(data) {
		return nil, NewGuestError(CodeInput, "data must be valid JSON")
	}
	return []byte(`{"status":"ok"}`), nil
}

// Notify handles the "notify" op — v1 stub (optional, per KB c689).
func Notify(auth, data []byte) ([]byte, error) {
	// TODO: v1 stub
	return nil, nil
}
