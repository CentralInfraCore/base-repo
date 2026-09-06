# Self Checklist

## Alapkövetelmények
- [ ] `make test` zöld (182 teszt, 89%+ coverage)
- [ ] Signing formátum megőrzött (`[signing-metadata]` + `[certificate]` blokk)
- [ ] Titkot nem commit-oltam (token, cert, PAT, private key)
- [ ] Változás diff + indoklás leírva

## Vault integráció
- [ ] `VAULT_ADDR` env változóból olvasva, nem hardcode
- [ ] Token fájlból olvasva (`/var/run/secrets/vault-token` vagy `CIC_VAULT_TOKEN_FILE`)
- [ ] CA cert fájlból olvasva (`/var/run/secrets/vault-ca.crt` vagy `CIC_VAULT_CA_FILE`)
- [ ] `prehashed: true`, `hash_algorithm: sha2-256` — nem változott
- [ ] Hiányzó token esetén: egyértelmű hibaüzenet, exit 1

## Docker
- [ ] `host.docker.internal:host-gateway` extra_hosts — Linux kompatibilitás
- [ ] Bind mountok: token + CA cert read-only
- [ ] `.env` fájl referencia titkokhoz (nem hardcode a compose-ban)
- [ ] Image verzió pinned vagy indokolt a `latest` használata

## Kód minőség
- [ ] Új Python kód: típusannotáció ahol van mintakód
- [ ] Új shell script: `set -euo pipefail` a fejlécben
- [ ] `project.schema.yaml` frissítve ha új `project.yaml` mező kerül be
- [ ] Makefile target: `##` komment a help outputhoz

## repo_type tudatosság
- [ ] Schema-specifikus logika `_require_repo_type("schema")` mögé zárva
- [ ] Új parancs: compiler.py subparser + infra.py metódus együtt