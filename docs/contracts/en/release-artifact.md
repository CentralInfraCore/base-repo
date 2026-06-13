# Release Artifact Contract

This document describes the integrity mechanisms that tie
`module/module.wasm` to `project.yaml`, and to the repository as a whole, and
the target state for a "provable, signed" release artifact. See also
[wasm-abi.md](wasm-abi.md).

## buildHash: module.wasm <-> project.yaml

`project.yaml`'s `metadata.buildHash` is the sha256 of `module/module.wasm`:

```yaml
metadata:
  buildHash: "cb069c11921ff1f8fe448a825c92683289b5f1a92db94e0cd910c1815ceff58b"
```

- `make wasm.build` (TinyGo build, `mk/wasm.mk`) compiles
  `module/module.wasm` and then runs
  `python -m tools.compiler set-build-hash`, which recomputes the sha256 and
  rewrites `metadata.buildHash` via a stdlib-only regex edit (deliberately
  avoiding a `tools.infra`/`tools.compiler` round trip for this single field).
- `make wasm.rebuild-verify` (`mk/wasm.mk`) is the **read-only counterpart**:
  it rebuilds `module/module.wasm` to a scratch path (`/tmp`, never
  overwriting the committed artifact), computes its sha256, and compares it
  against the committed `metadata.buildHash`. A mismatch fails with a message
  pointing at `make wasm.build` as the fix. This is the CI gate that proves
  the committed `module.wasm` binary is what `module/*.go` actually compiles
  to — i.e. that the artifact is reproducible from source, not hand-edited or
  stale.
- Both checks are wired into CI (`.github/workflows/ci.yml`): `wasm.build`
  runs first (so a from-scratch checkout always has a `module.wasm` to
  verify), then `wasm.rebuild-verify`, then `wasm.test`.

## ABI manifest: project.yaml <-> module.wasm exports

`project.yaml`'s `abi:` block (see [wasm-abi.md](wasm-abi.md#abi-version)) is
a second, independent link between the manifest and the compiled binary:
`module/abi_manifest_test.go` (part of `make wasm.test`) parses `abi.exports`
out of `project.yaml` and checks each name against
`module/module.wasm`'s actual exported functions (via wazero's
`instance.ExportedFunction`). This catches the case where source code changes
remove or rename an exported function but `project.yaml` is not updated —
independently of whether the binary content (buildHash) changed.

## MANIFEST.sha256: repository-wide integrity

`MANIFEST.sha256` (root of the repo) is a sorted `sha256sum` listing of every
git-tracked file (`make manifest-update`, `mk/Makefile`). `make
manifest-verify` re-runs `sha256sum -c` against it. This is the
coarsest-grained integrity check — it catches *any* tracked file changing
(including `module/module.wasm`, `project.yaml`, docs, `Makefile`s) but does
not by itself say *which* invariant (buildHash, ABI manifest, doc links) was
violated. `buildHash` and the ABI manifest are the targeted, semantic checks;
`MANIFEST.sha256` is the blunt "did anything in the tree change unexpectedly"
check, most useful for detecting drift between a signed release commit and
the working tree.

## Three-phase release (prepare / build-gap / finalize)

`tools/infra.py` / `tools/compiler.py` implement a three-phase release
process (`make release VERSION=X.Y.Z`):

1. **prepare** — validate schemas, bump version metadata.
2. **build-gap** — the window in which build artifacts (such as
   `module/module.wasm`) are produced and `metadata.buildHash` is set.
3. **finalize** — checksum and Vault-sign the release.

This template's `wasm.build` / `wasm.rebuild-verify` / ABI-manifest checks
fit into the **build-gap** phase: they are the mechanism by which a WASM
guest module's binary artifact and its manifest declarations are produced and
verified to be self-consistent *before* `finalize` checksums and signs the
result.

## Target state: provable signed release bundle

The current implemented state — `buildHash` + `wasm.rebuild-verify` + ABI
manifest + `MANIFEST.sha256` — establishes that, for a given commit:

- `module/module.wasm` is exactly what `module/*.go` compiles to
  (reproducible build).
- `module/module.wasm`'s exports match what `project.yaml` declares (ABI
  manifest).
- No other tracked file has drifted unexpectedly (repository manifest).

The target state for a release **artifact** (a distributable bundle, as
opposed to a signed source commit) builds on these three invariants: a bundle
containing `module/module.wasm` + `project.yaml` + a Vault signature over both
would let a downstream consumer verify, offline, that (a) the wasm binary
matches the declared `buildHash`, (b) the declared `abi.exports`/`operations`
match the binary's actual exports, and (c) the bundle was signed by a trusted
CIC key — without needing the source tree or a TinyGo toolchain at all.

Defining that bundle format, a `verify-release` CLI to check it, and how it
composes with the existing three-phase `tools/infra.py` release process are
**out of scope for this job** (2nd/3rd-tier review items) — see the job
report for the explicit "blocked by 3-tier architectural decision" note. This
document describes the target shape so that a future job can implement it
against the invariants already established here.
