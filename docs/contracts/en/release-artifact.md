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

`tools/finalize_release.py` is **deprecated and dead code** on this path: it
has no call site in `Makefile`, `mk/*.mk`, or `.github/workflows/*.yml`, and
the **finalize** phase above is implemented by `tools.infra.ReleaseManager`
(see `tools/infra.py:352-385`'s checksum + `buildHash` signing model), not by
this script. It is retained only pending a relay-readiness milestone (cf.
CIC-Schemas `compiler-architecture-plan.md`, "Step 10") and is marked
`# DEPRECATED` in the module itself.

## project.yaml schema: abi: block and provenance metadata

`project.schema.yaml` models `project.yaml`'s actual top-level and
`metadata`/`compiler_settings` keys (including `tags`, `validatedBy`,
`createdBy`, `build_timestamp`, `validity`, `checksum`, `sign`, `buildHash`,
`cicSign`, `cicSignedCA`), with `additionalProperties: false` on `metadata`,
`compiler_settings`, and `abi`. The `abi:` block has its own schema,
`abi.schema.yaml`, referenced from `project.schema.yaml` via `$ref`.

`abi.schema.yaml` is written in JSON syntax (a valid YAML subset): jsonref's
default loader (used by `tools.infra.load_and_resolve_schema`) only resolves
`$ref`s to JSON documents, not YAML block syntax — see `tools/infra.py:73-87`.
Writing the referenced file as JSON-in-`.yaml` keeps a single source of truth
for the `abi:` shape without modifying `tools/infra.py`.

TBD placeholder fields (`createdBy`, `cicSign`, `validatedBy.checksum`,
`checksum`, `sign`, `cicSignedCA`) remain typed as `string`/`object` with no
format constraints, so a template/unreleased `project.yaml` stays
schema-valid — see the field-level `description`s in `project.schema.yaml`
for what each placeholder means and which job fills it in.

## verify-release: offline release-readiness check

**Implemented** (this job). `make verify-release`
(`tools/verify_release.py`, `Makefile` `verify-release` target) runs a single
offline command that checks:

1. `project.yaml` validates against `project.schema.yaml` (incl. `abi:` via
   `abi.schema.yaml`).
2. `module/module.wasm`'s sha256 matches `project.yaml`'s
   `metadata.buildHash`, by rebuilding to a scratch path with the same
   TinyGo invocation as `make wasm.rebuild-verify` (`mk/wasm.mk`).
3. `project.yaml`'s `abi.exports` match `module/module.wasm`'s actual
   exports, by running
   `module/abi_manifest_test.go`'s `TestHostLoadABIManifestExportsPresent`
   (`go test`).
4. `MANIFEST.sha256` matches the working tree (same as `make
   manifest-verify`).
5. Provenance fields (`createdBy`, `validatedBy.checksum`, `checksum`,
   `sign`, `cicSign`, `cicSignedCA.certificate`) are reported as
   `OK` / `TBD` / `MISSING`.

Checks 1-4 gate the exit code (non-zero on any `FAIL`); check 5 is
**informational only**.

### What `verify-release` does NOT check

- **No cryptographic signature verification.** Check 5 reports whether
  `createdBy`/`cicSign`/`cicSignedCA`/`sign`/`checksum` are present,
  `"TBD"`, or missing — it does not call Vault and does not verify any
  certificate chain or signature. A `PASS` from `verify-release` is **not**
  proof that the commit was signed by a trusted CIC key.
- **No `repository_tree_hash`/`signing_metadata` check** (the `release:`
  block in `project.schema.yaml`) — that block is populated by `make release`
  and is out of scope here.
- **No network/Vault access** — by design, so the command works in CI and on
  a developer machine without Vault credentials.

A `TBD` result on check 5 is expected for a template/unreleased
`project.yaml` and does not fail the command; a `MISSING` result means the
metadata key itself is absent from `project.yaml` (a schema problem, also
caught by check 1).

`verify-release` is **not** wired into `.github/workflows/ci.yml` in this
job: it is a release-readiness gate (relevant when preparing a `make release`
run), not a per-push check like `wasm.rebuild-verify`/`wasm.test`/
`manifest-verify`. A future job can decide whether/where to add it as a CI
step (e.g. only on release branches).
## Target state: provable signed release bundle

The implemented state — `buildHash` + `wasm.rebuild-verify` + ABI manifest +
`MANIFEST.sha256` + `project.yaml`/`abi.schema.yaml` schema validation +
`verify-release` — establishes that, for a given commit:

- `module/module.wasm` is exactly what `module/*.go` compiles to
  (reproducible build).
- `module/module.wasm`'s exports match what `project.yaml` declares (ABI
  manifest).
- No other tracked file has drifted unexpectedly (repository manifest).
- `project.yaml`'s structure (including the `abi:` contract) matches the
  documented schema.

The target state for a release **artifact** (a distributable bundle, as
opposed to a signed source commit) builds on these invariants: a bundle
containing `module/module.wasm` + `project.yaml` + a Vault signature over both
would let a downstream consumer verify, offline, that (a) the wasm binary
matches the declared `buildHash`, (b) the declared `abi.exports`/`operations`
match the binary's actual exports, (c) `project.yaml` is schema-valid, and
(d) the bundle was signed by a trusted CIC key — without needing the source
tree or a TinyGo toolchain at all. `verify-release` implements (a)-(c); (d)
(actual cryptographic signature verification of `cicSign`/`createdBy.certificate`
against a CIC Root CA, without Vault access) remains **TBD** — see "What
`verify-release` does NOT check" above.

Defining that bundle format and how it composes with the existing
three-phase `tools/infra.py` release process is **out of scope for this job**
(3rd-tier review item, `wasm-release-pipeline-audit`) — see the job report
for the explicit "blocked by release-pipeline audit" note.
