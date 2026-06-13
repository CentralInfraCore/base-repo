# Authoring a WASM Guest Module

This template provides the boilerplate for a CIC iSDK guest module: a small
WASM binary, built with TinyGo, that the relay host (`CIC-Relay/core/cabinet`)
loads via [wazero](https://wazero.io) and drives through the `Call` ABI.

## Where to write your code

| File | Edit it? | Purpose |
|---|---|---|
| `module/abi.go` | **No** | iSDK boilerplate. Implements the host-required ABI (`allocate`, `deallocate`, `Call`) and dispatches op-strings to your handlers. |
| `module/handlers.go` | **Yes** | Your module's domain logic. Implement `Init`, `Process`, `Get`, `Notify`. |
| `module/module_loadtest_test.go` | Usually no | Host-load smoke test (`make wasm.test`) — extend it if your module needs additional round-trip coverage. |

Everything you need to implement lives in `handlers.go`:

```go
//go:build wasip1

package main

func Init(auth, data []byte) ([]byte, error)    { /* bring-up/config */ return nil, nil }
func Process(auth, data []byte) ([]byte, error) { /* main op */ return nil, nil }
func Get(auth, data []byte) ([]byte, error)     { /* idempotent read */ return []byte(`{"status":"ok"}`), nil }
func Notify(auth, data []byte) ([]byte, error)  { /* v1 stub */ return nil, nil }
```

To report a specific error code instead of the `RUNTIME` default, return a
`*GuestError` via `NewGuestError` (`module/envelope.go`):

```go
func Get(auth, data []byte) ([]byte, error) {
	if len(data) > 0 && !json.Valid(data) {
		return nil, NewGuestError(CodeInput, "data must be valid JSON")
	}
	return []byte(`{"status":"ok"}`), nil
}
```

## The contract (iSDK v1, KB `c689`)

Each handler receives two JSON byte slices — `auth` (the auth/context object)
and `data` (the op's input payload) — and returns `(dataJSON, error)`:

- On success, return the JSON payload for `data` (or `nil` for an empty
  result) and a `nil` error.
- On failure, return a non-nil `error`:
  - A plain `error` (e.g. from `fmt.Errorf`) is wrapped by `abi.go` as
    `{"data":null,"error":{"code":"RUNTIME","message":"..."}}` — the default
    code for unexpected/internal failures.
  - To report a specific code, return `*GuestError` via
    `NewGuestError(code, message)` (`module/envelope.go`). `abi.go` unwraps
    it and uses `code` directly instead of the `RUNTIME` default.
- `op` ∈ `{init, process, get, notify}`. An unknown op returns
  `{"error":{"code":"INPUT", ...}}` — you never see it in `handlers.go`.
- Error codes (`module/envelope.go`: `CodeInput`, `CodeRuntime`, `CodeInternal`,
  `CodeResource`, `CodeTimeout`): `INPUT | RUNTIME | INTERNAL | RESOURCE |
  TIMEOUT`. Use `INPUT` for bad caller data (e.g. JSON you can't parse),
  `RESOURCE` / `TIMEOUT` for environment-level failures, `INTERNAL` for bugs
  — see `Get` in `handlers.go` for a `CodeInput` example.
- v1 is **synchronous, deterministic, WASI-off**: no goroutines, no network,
  no filesystem, no wall-clock-dependent behaviour. `notify` is an optional
  stub in v1.

The host wraps every response in a `{data, error}` envelope
(`CIC-Relay/core/cabinet/cicwasm.go:346`) — `abi.go` does this for you via
`marshalData` / `marshalErr`. You only ever produce the inner `data` payload.

## Building and testing

The toolchain (TinyGo, Go, wazero) lives in the `builder` container — there is
no host-side install step.

```sh
make up              # start the builder container
make wasm.build      # TinyGo build -> module/module.wasm, fills project.yaml metadata.buildHash
make wasm.test       # host-load module.wasm with wazero, Call("get", "{}", "{}")
```

`make wasm.build` runs:

```
tinygo build -o module.wasm -target wasip1 -scheduler=none .
```

inside `module/`, then computes `sha256(module.wasm)` and writes it into
`project.yaml`'s `metadata.buildHash` (`mk/wasm.mk`, `tools/compiler.py
set-build-hash`).

`make wasm.test` runs `module/module_loadtest_test.go`, which:

1. instantiates `module.wasm` with wazero + `wasi_snapshot_preview1`
   (no `_start` — guest modules are libraries, not applications);
2. asserts the module exports `Call`, `allocate`, `deallocate`
   (`CIC-Relay/core/cabinet/cicwasm.go:243-247`);
3. calls `Call("get", "{}", "{}")` and decodes the `{data, error}` envelope.

If `module.wasm` doesn't exist yet, the test is skipped with a message
pointing at `make wasm.build`.

## Reproducible build check

`make wasm.rebuild-verify` rebuilds the guest module to a scratch path
(`/tmp` inside the builder container — it never overwrites the committed
`module/module.wasm`), computes its sha256, and compares it against
`project.yaml`'s `metadata.buildHash`. A mismatch means either the committed
`module.wasm` is stale (someone edited `module/` without running `make
wasm.build`) or the TinyGo build is not reproducible in this environment —
either way, the command fails with a non-zero exit and a message pointing at
`make wasm.build` to refresh both files. This runs in CI right after
`wasm.build` (`.github/workflows/ci.yml`).

## Go quality gate

`mk/golang.mk` is wired to operate on `module/` (`GO_MODULE_DIR=module`):

```sh
make golang.quality   # gofmt -s, staticcheck, go vet, govulncheck on module/
```

This runs in CI alongside `wasm.build` / `wasm.test`
(`.github/workflows/ci.yml`).

## Release / signing

`make release VERSION=x.y.z` runs the standard three-phase release
(`tools/infra.py`, inherited from the schemas template):

1. **Prepare** — checksums the source spec, creates the release branch.
2. **Build gap** — you run `make wasm.build` here; it fills
   `metadata.buildHash`.
3. **Finalize** — `_validate_final_project_yaml` now *requires*
   `metadata.buildHash` to be non-empty, and `_resign_with_build_hash`
   re-signs `project.yaml`'s metadata so the Vault signature covers both the
   source-spec checksum *and* the binary hash — a single signature binding
   provenance and integrity together.
