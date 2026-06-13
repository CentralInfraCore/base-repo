# Host Expectations Contract

This document describes what the relay host
(`CIC-Relay/core/cabinet/cicwasm.go`) does around every `Call`, and what a
guest module (this template) may assume — or must not assume — about that
environment. See also [wasm-abi.md](wasm-abi.md) and
[envelope.md](envelope.md).

## Instantiation

- The host runs the guest under [wazero](https://wazero.io), with the
  `wasi_snapshot_preview1` module instantiated (`cicwasm.go:70`) because
  TinyGo's `wasip1` target links against it — **not** because guest code is
  permitted to make WASI syscalls (v1 is WASI-off per
  [wasm-abi.md](wasm-abi.md)).
- The module is instantiated with `wazero.NewModuleConfig().WithStartFunctions()`
  (`cicwasm.go:178`) — i.e. **`_start` is never called**. Guest modules are
  libraries, not applications. `module/module_loadtest_test.go` mirrors this
  exactly.
- `newCicWasmHost` (`cicwasm.go:243`) fails fast if the compiled module does
  not export `Call`, `allocate`, and `deallocate` — see
  [wasm-abi.md](wasm-abi.md#required-wasm-exports).

## Per-call sequence (`callGuest`, `cicwasm.go:267-`)

For each of `Init` / `Process` / `Get` / `Notify`, the host:

1. `allocate`s and `Memory().Write`s the `op` string into guest memory.
2. `allocate`s and `Memory().Write`s the `authContextJson` string.
3. `allocate`s and `Memory().Write`s the `inputJson` (data) string.
4. Calls `Call(opPtr, opLen, authPtr, authLen, dataPtr, dataLen)` under a
   per-call timeout (`WasmManagerConfig.DefaultTimeoutSeconds`).
5. Unpacks the returned `uint64` as `(size << 32) | pointer`
   ([envelope.md](envelope.md#wire-transport-packunpack)).
6. `Memory().Read`s the result bytes, JSON-decodes the `{data, error}`
   envelope.
7. `deallocate`s all four buffers (op, auth, data, result) — including on
   error paths (`defer`).

A guest module's `Call` implementation (`module/abi.go`) only ever sees
step 4 onward; steps 1-3 and 7 are host responsibilities a module author
never implements directly, but `module/module_loadtest_test.go`'s
`callOp`/`writeString` helpers re-implement them for the host-load test.

## Memory-boundary contract

- The host only ever passes `ptr`/`len` pairs to `Call` for which the
  preceding `Memory().Write` succeeded. `wazero`'s `Memory().Write` and
  `Memory().Read` return `ok=false` (rather than panicking) for any
  out-of-bounds access — verified directly by
  `module/abi_negative_test.go`'s `TestHostMemoryOutOfBoundsAccess`.
- If `writeStringToWasm` fails (e.g. allocation failure), `callGuest`
  returns a `HOST_ERROR` envelope **before** calling `Call` — the guest
  never observes an invalid `ptr`/`len`.
- `module/abi.go`'s `readBytes`/`readString` (guest side) have **no
  independent bounds-check** — they trust the host's invariant above. This
  is intentional: the guest cannot safely validate pointers into its own
  linear memory beyond what the host already guarantees, and TinyGo's
  `unsafe.Slice` would panic/trap on a genuinely invalid pointer rather than
  return an error. The boundary is enforced once, on the host side.

## Host-side error envelopes

In addition to the guest-produced `{data, error}` envelope
([envelope.md](envelope.md)), `cicwasm.go`'s `callGuest` can itself produce
an error *before* or *instead of* calling the guest, via
`formatErrorJson(code, message, ...)`:

| Code | When |
|---|---|
| `HOST_ERROR` | Failed to write a buffer into guest memory, or failed to read/decode the result. |
| `TIMEOUT` | `context.DeadlineExceeded` while waiting for `Call` to return. |
| `RUNTIME` | `Call` itself returned a Go error (e.g. a wazero trap). |

These are **host-level** envelopes — distinct from the guest's
`{"error":{"code":"TIMEOUT",...}}` ([envelope.md](envelope.md#error-codes)).
A module author cannot produce `HOST_ERROR` from `handlers.go`; it indicates
a host/runtime-level failure that never reached the guest's dispatcher.

## Packed-zero result

A packed result of `0` (`ptr=0, len=0`) is treated by the host as
`data="null", error="null"` (`cicwasm.go:337-339`) without attempting a
`Memory().Read`. `module/abi.go`'s `pack` only returns `0` for a zero-length
byte slice, which `marshalData`/`marshalErr` never produce — see
[envelope.md](envelope.md#wire-transport-packunpack).

## Timeouts and resource limits

- `WasmManagerConfig.DefaultTimeoutSeconds` bounds every `Call` via
  `context.WithTimeout` (`cicwasm.go:267`).
- `WasmManagerConfig.DefaultMemoryPages` and the LRU `compiledModules` cache
  bound compiled-module memory; eviction closes the underlying
  `wazero.CompiledModule` (`cicwasm.go:96-104`).
- Guest code (v1) has no mechanism to request more time or memory than these
  host-configured limits — `RESOURCE`/`TIMEOUT` `GuestError`s
  ([envelope.md](envelope.md#error-codes)) are for **handler-detected**
  resource issues (e.g. a sub-operation hitting its own internal limit), not
  for negotiating host limits.
