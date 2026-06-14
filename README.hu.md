# CIC WASM Modul Sablon

Ez a repository egy sablon **CIC iSDK guest modul** elkészítéséhez: egy kicsi,
TinyGo-val épített WASM bináris, amelyet a relay host
(`CIC-Relay/core/cabinet`) [wazero](https://wazero.io)-n keresztül tölt be és
a `Call` ABI-n keresztül vezérel — beépített, kriptográfiailag aláírt release
pipeline-nal.

## Áttekintés

- **Modul:** A domain logikát a `module/handlers.go`-ban implementáld az
  iSDK v1 `Call` ABI szerint (`init` / `process` / `get` / `notify`). A teljes
  szerződésért és a hibatípus-konvenciókért lásd a
  **[WASM Modul Szerzői Útmutatót](docs/hu/wasm-module-authoring.md)**.
- **Build és host-load teszt:** a `make wasm.build` TinyGo-val fordítja a
  guest modult; a `make wasm.test` betölti a `module/module.wasm`-ot ugyanazzal
  a wazero runtime-mal, amit a relay cabinet használ, és végigteszteli az ABI-t.
- **ABI manifest:** a `project.yaml` `abi:` blokkja (exports/operations/
  envelopeVersion) deklarálja a guest <-> host szerződést; a `make wasm.test`
  elbukik, ha a `module/module.wasm` nem exportálja mindazt, amit deklarál.
  Lásd: **[WASM ABI szerződés](docs/contracts/hu/wasm-abi.md)**.
- **Eredetigazolás (provenance):** minden release aláírja a forrás-spec
  checksumot (`project.yaml`) ÉS a felépített artifact `buildHash`-ét
  (`sha256(module/module.wasm)`), így a kiadott modul végponttól végpontig
  "bizonyítható, aláírt artifact".

A rendszer architektúrájának és a kiadási folyamat részletes leírásáért,
kérlek, olvasd el az **[Architektúra Áttekintés](docs/hu/architecture.md)**
dokumentumot.

---

## Első Lépések

Ez a szekció végigvezet a projekt kezdeti beállításán.

### Előfeltételek

- `docker`
- `docker-compose`
- `make`
- `git`

### Gyors Kezdés

1.  **Indítsd el a Vault Aláíró Ügynököt:**
    Egy segédszkript biztosít egy helyi Vault szervert a fejlesztéshez. Ennek egy külön terminálban kell futnia.
    ```sh
    # A szkript --help kapcsolója megmutatja az összes opciót
    ./tools/vault-sign-agent.sh -k <kulcs.pem> -c <cert.crt> --root-ca-file <root.pem>
    ```

2.  **Inicializáld a Környezetet:**
    Ezek a parancsok telepítik a függőségeket, megépítik a Docker image-et, elindítják a konténert, és beállítják a Git hook-okat.
    ```sh
    make infra.deps
    make build
    make up
    make repo.init
    ```

3.  **Építsd fel és teszteld a WASM modult:**
    ```sh
    make wasm.build
    make wasm.test
    ```

A környezeted most már készen áll. A napi fejlesztési feladatokról és a kiadások létrehozásáról szóló részletes útmutatóért, kérlek, olvasd el a **[Fejlesztői Munkafolyamat](docs/hu/workflow.md)** dokumentumot.

---

## Makefile Parancsok

A `Makefile` egy egyszerű interfészt biztosít az összes gyakori feladathoz.

- `make wasm.build`: A `module/module.wasm` felépítése TinyGo-val és a `buildHash` kiszámítása.
- `make wasm.rebuild-verify`: A guest modul újraépítése egy ideiglenes helyre, és a sha256 összevetése a `project.yaml` `metadata.buildHash` mezőjével — elkapja, ha a `module.wasm` elavult vagy nem reprodukálható.
- `make wasm.test`: A `module.wasm` host-load tesztje a relay cabinet ABI ellen (wazero).
- `make validate`: A helyi séma módosításainak validálása.
- `make test`: A Python tesztcsomag futtatása.
- `make check`: Az összes kódminőségi ellenőrzés (linting, formázás, típusellenőrzés) futtatása.
- `make golang.quality`: Go minőségi kapu (fmt/vet/lint/vuln) a `module/`-ra.
- `make manifest-verify` / `make manifest-update`: A `MANIFEST.sha256` ellenőrzése/újragenerálása.
- `make verify-release`: Offline release-készenléti ellenőrzés — `project.yaml` séma (incl. `abi:`), `module.wasm` buildHash, ABI exportok, `MANIFEST.sha256`, és a provenance mezők státusza. Ld. [release-artifact.md](docs/contracts/hu/release-artifact.md).
- `make release VERSION=v1.2.3`: Új, aláírt kiadás létrehozása.

Az összes elérhető parancs teljes listájáért és leírásáért, kérlek, olvasd el a **[Makefile Súgó](docs/hu/makefile-cheatsheet.md)** dokumentumot.

---

## Örökölt: Séma Fordító és Aláíró Infrastruktúra

A sablon release/aláíró pipeline-ja (`tools/`, `mk/infra.mk`,
`project.yaml` + `project.schema.yaml`) a CIC séma fordító ökoszisztémából
(`schemas/main`) öröklődött. Ez biztosítja:

- **Irányítás:** Minden sémának meg kell felelnie egy központi meta-sémának.
- **Biztonság:** Az aláírást a HashiCorp Vault kezeli, biztosítva, hogy a privát kulcsok soha ne kerüljenek ki.
- **Reprodukálhatóság:** A teljes környezet Docker konténerekben fut.

Ez a fenti WASM modul sablon alatt húzódó alapréteg — a sablon legtöbb
felhasználójának a `make release`-en túl nincs szüksége vele közvetlenül
foglalkozni.
