# Base-Repo Roadmap (AI snapshot)

Ez a fájl az AI-támogatott roadmap állapota.

---

## Mérföldkövek (prioritási sorrend)

### M1 — Unified Compiler Architecture (schemalib)
* **Állapot:** Kész
* **Összefoglalás:** `tools/schemalib/` létrehozva (loader, validator, artifact), `tools/infra.py` refaktorálva repo_type routing-gal, `tools/compiler.py` kibővítve (`release-dependency`, `release-schema`, `get-name`). 182 teszt, 89% coverage.

### M2 — Renovate Vault Signing
* **Állapot:** Tervezett
* **Fő cél:** Self-hosted Renovate runner, amely ugyanazzal a Vault ECDSA mechanizmussal írja alá a commitjait, mint a fejlesztői commitok. A signing formátum egységes: `[signing-metadata]` + `[certificate]` blokk.
* **Branch:** `d/feature-003`
* **DoD:**
  * `docker/renovate/` könyvtár létezik a szükséges fájlokkal
  * `make renovate.run` elindítja a Renovate containert
  * Renovate által létrehozott commit tartalmaz érvényes `[signing-metadata]` blokkot
  * `RENOVATE_DRY_RUN=full` módban a hook meghívódik, de commit nem keletkezik
  * `make test` változatlanul zöld

### M3 — Relay-alapú CIC Central Signing
* **Állapot:** Tervezett (előfeltétel: CIC-Relay trust ecosystem bootstrap)
* **Fő cél:** A `tools/finalize_release.py` ideiglenes szkript lecserélése a CIC-Relay recorder komponensére. A `cicSign` + `cicSignedCA` kitöltése automatizálttá válik.