# System Context (AI számára)

Olvasd el mielőtt bármit módosítasz.

---

## Mi ez a rendszer?

A `base-repo` egy **infrastruktúra sablon**. Nem tartalmaz üzleti logikát — a szerepe az, hogy a belőle
származtatott production repók (pl. CIC-Schemas, CIC-Relay) egységes build, signing és release
infrastruktúrát örököljenek Renovate-en keresztül.

A bizalom alapja: minden commit és release artefaktum kriptográfiailag aláírt.
Az aláírás Vault Transit ECDSA SHA256 alapú, a tanúsítványlánc a CICRootCA-ig visszakövethető.

---

## A három réteg

```
tools/compiler.py     CLI belépési pont — argument parsing, service wiring
tools/infra.py        ReleaseManager — Git/Vault workflow orchestrátor
tools/schemalib/      Schema pipeline library (csak repo_type=schema esetén aktív)
  ├── loader.py       YAML betöltés $ref feloldással
  ├── validator.py    Integritás ellenőrzés + jsonschema validálás
  └── artifact.py     Checksum, signing payload, artefaktum összeállítás
tools/releaselib/     Git/Vault service absztrakciók
  ├── git_service.py
  ├── vault_service.py
  └── exceptions.py
tools/finalize_release.py  IDEIGLENES — CIC central signing (relay váltja fel)
```

---

## A signing mechanizmus

Az aláíró eszközkészlet a `cic-factory-core`-ból van átemelve, az SPDX sor
kivételével változtatás nélkül (a kódkommentek `#NN` hivatkozásai a
`cic-factory-core` issue-ira mutatnak). Licenc: itt **MIT**, mert ebből a
template-ből örököl minden repó, a partnerek kereskedelmi moduljai is; a
`cic-factory-core`-ban ugyanez a kód AGPL-3.0-or-later. Szinkron ellenőrzése:
`diff <(grep -v SPDX-License-Identifier A) <(grep -v SPDX-License-Identifier B)`. Belépési pont: `tools/init-hooks.sh` (`make repo.init`), ami symlinket
tesz a `commit-msg` és a `post-rewrite` hookra, majd a
`tools/check-hook-provenance.sh`-val ellenőrzi, hogy tényleg az hat.

`tools/git_hook_commit-msg.sh` — minden `git commit` triggereli:

1. `git write-tree` → staged tree snapshot
2. Vault KV: `GET /v1/cic-my-sign-key/data/crt` → PEM tanúsítvány (aláírás ELŐTT)
3. `cic-tree-manifest/v4` → SHA256 digest (base64). A manifest köti: az aláíró
   nyilvános kulcsát (a tanúsítványból), a szerzőt, a committert, az üzenet
   digestjét és a fa minden bejegyzését (mode, típus, OID, path — a gitlinket is)
4. Vault Transit: `POST /v1/transit/sign/cic-my-sign-key` (prehashed ECDSA)
5. Önellenőrzés: az aláírás érvényes-e a tanúsítvány kulcsára — ha nem, a commit megáll
6. `[signing-metadata]` (benne `manifest = …`) + `[certificate]` blokk → commit message végére

A Vault CA nélkül és nem-https címre a hook nem ír alá; a token egy 0600-as
curl-configban utazik, nem a parancssorban (`tools/lib-vault-sign.sh`).

**A blokk szerkezete invariáns** (`[signing-metadata]` + `[certificate]`). A
digest jelentését a `manifest =` sor mondja meg; a verifier a v1 (tar), v2, v3 és
v4 aláírásokat is ellenőrzi, ismeretlen verziót elutasít.

| Eszköz | Mire |
|---|---|
| `tools/verify-signatures.sh --range A..B` / `--tag <név>` | offline ellenőrzés: digest újraszámolás + ECDSA a beágyazott tanúsítványra |
| `tools/resign-range.sh <upstream>` | rebase után újraaláírás (a rebase nem futtatja a hookot) |
| `tools/git_hook_post-rewrite.sh` | rebase/amend után szól, ha elavult aláírás maradt |
| `tools/sign-release-tag.sh` | release tag aláírása (`cic-tag-manifest/v1`) |
| `tools/check-hook-provenance.sh` | a hatályos hook a kiadott signer-e (viselkedési próba) |

**Amit az aláírás NEM állít:** a kulcs kötött, de nem megbízható — a verifier
nem ellenőrzi, ki adta ki a tanúsítványt (bizalmi horgony: következő lépés,
`project.yaml` `issuer_certificate`). A commit OID-ja, a szülők és a dátumok
nincsenek kötve. A Renovate bot commitjai aláíratlanok, ezért a repó saját
történetére a verifier nem kapu.

Tesztek: `make test.signing` (a `make test` is lefuttatja) — hat bash suite,
hamis Vaulttal és eldobható kulccsal, token és hálózat nélkül.

---

## repo_type routing

A `project.yaml` `compiler_settings.repo_type` értéke határozza meg, mely parancsok elérhetők:

| repo_type | Elérhető parancsok |
|---|---|
| `module` | `release`, `get-name` |
| `schema` | `release`, `release-dependency`, `release-schema`, `validate`, `get-name` |
| `workflow` | `release`, `get-name` |

---

## Nyitott trust bootstrap probléma

A `finalize_release.py` ideiglenes megoldás a CIC central signing-re.
A végleges megoldás a CIC-Relay recorder komponense lesz — amikor a relay trust ecosystem bootstrapped.