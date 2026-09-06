# Base-Repo Roadmap (AI snapshot)

Ez a fájl az AI-támogatott roadmap állapota.

---

## Mérföldkövek (prioritási sorrend)

### M1 — Unified Compiler Architecture (schemalib)
* **Állapot:** Kész
* **Összefoglalás:** `tools/schemalib/` létrehozva (loader, validator, artifact), `tools/infra.py` refaktorálva repo_type routing-gal, `tools/compiler.py` kibővítve (`release-dependency`, `release-schema`, `get-name`). 182 teszt, 89% coverage.

### M2 — Relay-alapú CIC Central Signing
* **Állapot:** Tervezett (előfeltétel: CIC-Relay trust ecosystem bootstrap)
* **Fő cél:** A `tools/finalize_release.py` ideiglenes szkript lecserélése a CIC-Relay recorder komponensére. A `cicSign` + `cicSignedCA` kitöltése automatizálttá válik.