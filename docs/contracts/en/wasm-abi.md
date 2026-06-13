# WASM ABI Contract

This document is the standalone reference for the guest <-> host WASM ABI
(KB `c689`). For a tutorial on implementing a module against this ABI, see
the **[WASM Module Authoring Guide](../../en/wasm-module-authoring.md)**.

## ABI version

`project.yaml`'s `abi:` block is the machine-readable manifest:

```yaml
abi:
  name: wasm-module-template
  version: "1.0.0"
  envelopeVersion: 1
  exports:
    - allocate
    - deallocate
    - Call
  operations:
    - init
    - process
    - get
    - notify
```

`module/abi_manifest_test.go` (`TestABIManifestExportsPresent`, run by
`make wasm.test`) verifies that every name in `abi.exports` is actually
exported by the compiled `module/module.wasm` — a missing export fails the
build.

## Required WASM exports

The relay host (`CIC-Relay/core/cabinet/cicwasm.go:243-247`,
`newCicWasmHost`) requires exactly three exported functions from a guest
module:

| Export | Signature | Purpose |
|---|---|---|
| `allocate` | `(size uint32) -> uintptr` | Allocate `size` bytes in guest linear memory; returns a pointer the host can `Memory().Write` into. |
| `deallocate` | `(ptr uintptr, size uint32)` | Free a region previously returned by `allocate`. |
| `Call` | `(opPtr, opLen, authPtr, authLen, dataPtr, dataLen uint32) -> uint64` | Dispatch one op. Returns a packed `(size << 32) \| pointer` result (see [envelope.md](envelope.md)). |

These are implemented in `module/abi.go` and **must not be edited** by module
authors — it is iSDK boilerplate.

TinyGo's `wasip1` target also exports a handful of incidental functions
(`memory`, `malloc`, `free`, `calloc`, `realloc`, `_start`). These are not
part of the iSDK contract and are not declared in `abi.exports` — the host
never calls them directly (guest modules are libraries, not applications;
`_start` is never invoked, per `cicwasm.go:177-178`).

## Operations (`op` strings)

`Call`'s `op` argument selects a domain handler (`module/handlers.go`),
dispatched by `module/abi.go`:

| op | Handler | Notes |
|---|---|---|
| `init` | `Init(auth, data) ([]byte, error)` | Module bring-up / configuration. |
| `process` | `Process(auth, data) ([]byte, error)` | The module's main operation. |
| `get` | `Get(auth, data) ([]byte, error)` | Idempotent read. |
| `notify` | `Notify(auth, data) ([]byte, error)` | Optional v1 stub. |

Any other `op` string (including the empty string `""`) is rejected by
`abi.go`'s dispatcher with a `CodeInput` error envelope — see
[envelope.md](envelope.md) — without ever reaching `handlers.go`
(`module/abi_negative_test.go`: `TestHostLoadUnknownOp`,
`TestHostLoadEmptyOp`).

## v1 execution model

- **Synchronous**: one `Call` = one op, no async callbacks.
- **Deterministic**: no goroutines, no wall-clock-dependent behaviour.
- **WASI-off**: no filesystem or network access from guest code (the WASI
  snapshot is instantiated only because TinyGo's `wasip1` target requires
  it at link time — it is not a sanctioned capability for module code).

## Memory ownership

Both `op`, `auth`, and `data` buffers are written into guest memory by the
host (`Memory().Write`) before `Call`, and the *result* buffer is allocated
by the guest (via `allocate`, inside `Call`/`pack`) and freed by the host
(`Memory().Read` then `deallocate`) afterwards. See
[host-expectations.md](host-expectations.md) for the full sequence and the
memory-boundary contract.
