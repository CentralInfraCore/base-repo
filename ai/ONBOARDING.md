# Onboarding (AI)

## 1 perc alatt

- **Mi ez:** Schema Compiler & Signing Infrastructure Template. Ebből a repóból örökítenek a production repók (CIC-Schemas, CIC-Relay stb.) Renovate-en keresztül.
- **Entrypoint:** `tools/compiler.py` — CLI, `tools/infra.py` — ReleaseManager orchestrátor.
- **Signing mechanizmus:** `tools/git_hook_commit-msg.sh` — ECDSA SHA256 Vault Transit, `cic-tree-manifest/v4` digest (fa + szerző + committer + üzenet + aláíró kulcs) → signature + certificate a commit message-be. Ellenőrzés: `tools/verify-signatures.sh`. Forrás: `cic-factory-core`.
- **Schema pipeline (csak `repo_type: schema`):** `tools/schemalib/` — loader, validator, artifact.
- **Mérce:** `make test` — pytest suite, 89%+ coverage. Ez kell zöldnek lennie.
- **Konfiguráció:** `project.yaml` — minden repo saját példányban adja meg a `compiler_settings`-t.

## Mielőtt bármit írsz

Olvasd el: `ai/SYSTEM_CONTEXT.md`

**Ami kész, ne írd felül:**

| Implementált | Állapot |
|---|---|
| `tools/schemalib/` (loader, validator, artifact) | Kész, 100% fedettség |
| `tools/infra.py` repo_type routing | Kész |
| `tools/compiler.py` subcommands | Kész |
| `tools/git_hook_commit-msg.sh` + verify/resign/provenance/tag eszközök | `cic-factory-core`-ból átemelve; változtatás ott, nem itt |

## Hogyan ellenőrzöl

```bash
make test          # signing suite-ok + pytest — ez kell zöldnek
make test.signing  # csak az aláíró eszközök hat bash suite-ja
make validate      # schema validáció (csak schema repo_type)
make build         # Docker image build
```

## Ha gond van

Javasolj `project.yaml` schema változást (`project.schema.yaml`-hoz), ne térj el csendben a meglévő signing formátumtól.