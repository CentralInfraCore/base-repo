# Séma Fordító és Aláíró Infrastruktúra

Ez a repository egy robusztus, konténerizált fejlesztői környezetet biztosít verziózott séma definíciók létrehozásához, validálásához és kriptográfiai aláírásához.

## Áttekintés

A keretrendszer elsődleges célja egy irányított, biztonságos és reprodukálható munkafolyamat létrehozása a sémák kezelésére. Biztosítja, hogy minden séma validált, és integritása kriptográfiai aláírásokon keresztül ellenőrizhető.

- **Irányítás:** Minden sémának meg kell felelnie egy központi meta-sémának.
- **Biztonság:** Az aláírást a HashiCorp Vault kezeli, biztosítva, hogy a privát kulcsok soha ne kerüljenek ki.
- **Reprodukálhatóság:** A teljes környezet Docker konténerekben fut.

A rendszer architektúrájának és a kiadási folyamat részletes leírásáért, kérlek, olvasd el az **[Architektúra Áttekintés](docs/hu/architecture.md)** dokumentumot.

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

A környezeted most már készen áll. A napi fejlesztési feladatokról és a kiadások létrehozásáról szóló részletes útmutatóért, kérlek, olvasd el a **[Fejlesztői Munkafolyamat](docs/hu/workflow.md)** dokumentumot.

---

## Makefile Parancsok

A `Makefile` egy egyszerű interfészt biztosít az összes gyakori feladathoz.

- `make validate`: A helyi séma módosításainak validálása.
- `make test`: A Python tesztcsomag futtatása.
- `make check`: Az összes kódminőségi ellenőrzés (linting, formázás, típusellenőrzés) futtatása.
- `make release-dependency VERSION=v1.2.3`: Új, aláírt kiadás létrehozása egy függőségi sémából.

Az összes elérhető parancs teljes listájáért és leírásáért, kérlek, olvasd el a **[Makefile Súgó](docs/hu/makefile-cheatsheet.md)** dokumentumot.
