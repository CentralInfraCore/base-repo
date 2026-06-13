# JSON Envelope Contract

This document is the standalone reference for the `{data, error}` JSON
envelope produced by every `Call` (KB `c689`). See also
[wasm-abi.md](wasm-abi.md) for the surrounding ABI.

## Shape

Every `Call` returns one JSON object with exactly two top-level keys:

```json
{"data": <any JSON value> | null, "error": <GuestError> | null}
```

Exactly one of `data` / `error` is non-null:

- **Success**: `data` is the handler's JSON payload (or `null` for an empty
  result — the "null-success" case below), `error` is `null`.
- **Failure**: `data` is `null`, `error` is a `GuestError` object.

```go
// module/envelope.go
type guestResult struct {
    Data  json.RawMessage `json:"data"`
    Error json.RawMessage `json:"error"`
}
```

This mirrors the host's `GuestResult` struct
(`CIC-Relay/core/cabinet/cicwasm.go:346`).

## `GuestError` shape

```json
{"code": "INPUT", "message": "human-readable description"}
```

```go
// module/envelope.go
type guestError struct {
    Code    string `json:"code"`
    Message string `json:"message"`
}
```

## Error codes

Defined in `module/envelope.go`, per KB `c689`:

| Code | Meaning | Typical source |
|---|---|---|
| `INPUT` | Bad caller data (e.g. invalid JSON, unknown/empty `op`). | `handlers.go` via `NewGuestError(CodeInput, ...)`, or `abi.go`'s dispatcher for an unrecognized `op`. |
| `RUNTIME` | Unexpected/internal failure. **Default** for a plain (untyped) `error` returned from a handler. | `abi.go`'s `Call`, wrapping any non-`*GuestError`. |
| `INTERNAL` | A handler produced output that isn't valid JSON. | `marshalData` (`envelope.go`) — a defensive fallback so malformed JSON never reaches the host. |
| `RESOURCE` | Environment-level resource exhaustion. | Handler-specific, via `NewGuestError(CodeResource, ...)`. |
| `TIMEOUT` | The operation exceeded its time budget. | Handler-specific, via `NewGuestError(CodeTimeout, ...)`; the *host* also produces a `TIMEOUT` envelope at the `cicwasm.go` level on `context.DeadlineExceeded`, but with a different envelope shape — see [host-expectations.md](host-expectations.md). |

To report a specific code, a handler returns `*GuestError` via
`NewGuestError(code, message)`. A plain `error` (e.g. `fmt.Errorf(...)`) is
always wrapped as `CodeRuntime` by `abi.go`'s `Call`.

## Null-success contract

The template stubs for `init`, `process`, and `notify`
(`module/handlers.go`) return `(nil, nil)`. `marshalData(nil)` must produce:

```json
{"data": null, "error": null}
```

i.e. a **present, non-empty envelope** whose `data` field is the JSON
literal `null` — not an empty/zero result. This is verified by
`module/module_loadtest_test.go`'s `TestHostLoadNullSuccess` (payload
`"{}"`) and `module/abi_negative_test.go`'s
`TestHostLoadEmptyPayloadNullSuccess` (payload `""`).

This is distinct from the **packed-zero** case below, which the guest must
never produce for a `{data,error}` result.

## Wire transport: pack/unpack

`Call` does not return the envelope bytes directly — it returns a single
`uint64`:

```go
// module/abi.go
func pack(b []byte) uint64 {
    if len(b) == 0 {
        return 0 // host treats packed 0 as null/empty (cicwasm.go:337-339)
    }
    ptr := allocate(uint32(len(b)))
    copy(unsafe.Slice((*byte)(unsafe.Pointer(ptr)), len(b)), b)
    return (uint64(uint32(len(b))) << 32) | uint64(ptr)
}
```

- High 32 bits: result length.
- Low 32 bits: pointer into guest linear memory (allocated by `allocate`,
  freed by the host via `deallocate` after reading).
- A packed value of `0` (`ptr=0, len=0`) is host-side shorthand for
  `data="null", error="null"` (`cicwasm.go:337-339`) — but `marshalData` /
  `marshalErr` always produce a non-empty `{"data":...,"error":...}` byte
  string, so the guest's `Call` never legitimately returns packed `0` in
  practice. `module/module_loadtest_test.go`'s `callOp` helper treats a
  packed `0` result as a test failure for this reason.

## Versioning

`project.yaml`'s `abi.envelopeVersion` (currently `1`) identifies this
envelope shape. A future breaking change to the `{data, error}` structure
(e.g. adding required fields, changing error-code semantics) must bump
`envelopeVersion` and update this document.
