# Onboarding (AI)

## 1 perc alatt

- **Mi ez:** Schema Compiler & Signing Infrastructure Template. Ebből a repóból örökítenek a production repók (CIC-Schemas, CIC-Relay stb.) Renovate-en keresztül.
- **Entrypoint:** `tools/compiler.py` — CLI, `tools/infra.py` — ReleaseManager orchestrátor.
- **Signing mechanizmus:** `tools/git_hook_commit-msg.sh` — ECDSA SHA256 Vault Transit, staged tree digest → signature + certificate a commit message-be.
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
| `tools/git_hook_commit-msg.sh` signing hook | Referencia implementáció |

## Hogyan ellenőrzöl

```bash
make test          # pytest suite — ez kell zöldnek
make validate      # schema validáció (csak schema repo_type)
make build         # Docker image build
```

## Ha gond van

Javasolj `project.yaml` schema változást (`project.schema.yaml`-hoz), ne térj el csendben a meglévő signing formátumtól.