# Release artifact szerződés

Ez a dokumentum az integritás-mechanizmusokat írja le, amelyek a
`module/module.wasm`-ot a `project.yaml`-hoz, és a repository-t egészéhez
kötik, valamint a célállapotot egy "bizonyítható, aláírt" release artifact
számára. Lásd még [wasm-abi.md](wasm-abi.md).

## buildHash: module.wasm <-> project.yaml

A `project.yaml` `metadata.buildHash` mezője a `module/module.wasm` sha256-a:

```yaml
metadata:
  buildHash: "cb069c11921ff1f8fe448a825c92683289b5f1a92db94e0cd910c1815ceff58b"
```

- A `make wasm.build` (TinyGo build, `mk/wasm.mk`) lefordítja a
  `module/module.wasm`-ot, majd futtatja a
  `python -m tools.compiler set-build-hash`-t, amely újraszámolja a sha256-ot
  és átírja a `metadata.buildHash`-t egy stdlib-only regex-alapú
  szerkesztéssel (szándékosan elkerülve egy teljes
  `tools.infra`/`tools.compiler` round-tripet ehhez az egyetlen mezőhöz).
- A `make wasm.rebuild-verify` (`mk/wasm.mk`) ennek **csak-olvasó párja**: a
  `module/module.wasm`-ot egy scratch helyre (`/tmp`, sosem írja felül a
  commitolt artifactot) újra lefordítja, kiszámolja a sha256-ját, és
  összeveti a commitolt `metadata.buildHash`-sel. Eltérés esetén egy hibával
  bukik el, ami a `make wasm.build`-re mutat mint javításra. Ez az a CI gate,
  ami bizonyítja, hogy a commitolt `module.wasm` bináris az, amire a
  `module/*.go` valóban fordít — azaz hogy az artifact reprodukálható a
  forrásból, nincs kézzel szerkesztve vagy elavulva.
- Mindkét ellenőrzés be van kötve a CI-ba (`.github/workflows/ci.yml`): a
  `wasm.build` fut először (hogy egy friss checkout-nak mindig legyen
  `module.wasm`-ja, amit ellenőrizni lehet), majd a `wasm.rebuild-verify`,
  majd a `wasm.test`.

## ABI manifeszt: project.yaml <-> module.wasm exportok

A `project.yaml` `abi:` blokkja (lásd [wasm-abi.md](wasm-abi.md#abi-verzió))
egy második, független kapcsolat a manifeszt és a lefordított bináris
között: a `module/abi_manifest_test.go` (a `make wasm.test` része) kiolvassa
az `abi.exports`-ot a `project.yaml`-ból, és minden nevet összevet a
`module/module.wasm` tényleges exportált függvényeivel (a wazero
`instance.ExportedFunction`-jén keresztül). Ez azt az esetet kapja el,
amikor a forráskód-változás eltávolít vagy átnevez egy exportált
függvényt, de a `project.yaml` nincs frissítve — függetlenül attól, hogy a
bináris tartalma (buildHash) változott-e.

## MANIFEST.sha256: repository-szintű integritás

A `MANIFEST.sha256` (a repo gyökerében) egy rendezett `sha256sum` lista
minden git-tracked fájlról (`make manifest-update`, `mk/Makefile`). A `make
manifest-verify` újra futtatja a `sha256sum -c`-t ez ellen. Ez a
legdurvább szemcsézettségű integritásellenőrzés — *bármilyen* tracked fájl
változását elkapja (beleértve a `module/module.wasm`-ot, `project.yaml`-t,
docs-okat, `Makefile`-okat), de önmagában nem mondja meg, *melyik*
invariáns (buildHash, ABI manifeszt, doc linkek) sérült. A `buildHash` és az
ABI manifeszt a célzott, szemantikus ellenőrzések; a `MANIFEST.sha256` a
"változott-e bármi a fában váratlanul" tompa ellenőrzés, leginkább egy
aláírt release commit és a working tree közti drift detektálására hasznos.

## Háromfázisú release (prepare / build-gap / finalize)

A `tools/infra.py` / `tools/compiler.py` egy háromfázisú release folyamatot
implementál (`make release VERSION=X.Y.Z`):

1. **prepare** — sémák validálása, verzió-metaadat emelése.
2. **build-gap** — az az ablak, amelyben a build artifactok (mint a
   `module/module.wasm`) létrejönnek és a `metadata.buildHash` beállításra
   kerül.
3. **finalize** — a release checksum-olása és Vault-aláírása.

Ennek a template-nek a `wasm.build` / `wasm.rebuild-verify` / ABI-manifeszt
ellenőrzései a **build-gap** fázisba illeszkednek: ezek a mechanizmus, amivel
egy WASM guest modul bináris artifactja és a manifeszt-deklarációi
előállnak és ellenőrizve lesz, hogy önkonzisztensek, *mielőtt* a
`finalize` checksum-olja és aláírja az eredményt.

A `tools/finalize_release.py` **deprecated és dead code** ezen az úton: nincs
hívási helye a `Makefile`-ban, `mk/*.mk`-ban vagy
`.github/workflows/*.yml`-ben, és a fenti **finalize** fázist a
`tools.infra.ReleaseManager` implementálja (lásd `tools/infra.py:352-385`
checksum + `buildHash` aláírási modelljét), nem ez a script. Csak egy
relay-readiness milestone-ig marad meg (vö. CIC-Schemas
`compiler-architecture-plan.md`, "Step 10"), és a modulban `# DEPRECATED`
jelöléssel van ellátva.

## Célállapot: bizonyítható, aláírt release bundle

A jelenlegi implementált állapot — `buildHash` + `wasm.rebuild-verify` + ABI
manifeszt + `MANIFEST.sha256` — egy adott commitra megalapozza, hogy:

- a `module/module.wasm` pontosan az, amire a `module/*.go` fordul
  (reprodukálható build);
- a `module/module.wasm` exportjai megfelelnek annak, amit a `project.yaml`
  deklarál (ABI manifeszt);
- semmilyen más tracked fájl nem driftelt váratlanul (repository manifeszt).

A release **artifact** (egy disztribuálható bundle, szemben egy aláírt
forrás commit-tal) célállapota ezekre a három invariánsra épül: egy
`module/module.wasm` + `project.yaml` + egy Vault-aláírás mindkettő felett
bundle lehetővé tenné egy downstream fogyasztónak, hogy offline ellenőrizze:
(a) a wasm bináris megfelel a deklarált `buildHash`-nek, (b) a deklarált
`abi.exports`/`operations` megfelel a bináris tényleges exportjainak, és (c)
a bundle egy megbízható CIC kulccsal van aláírva — anélkül, hogy a
forrásfára vagy egy TinyGo toolchain-re szükség lenne.

Ennek a bundle formátumnak a definiálása, egy `verify-release` CLI a
ellenőrzéséhez, és hogy ez hogyan illeszkedik a meglévő háromfázisú
`tools/infra.py` release folyamathoz, **nem ennek a jobnak a hatóköre**
(2./3. tier review elemek) — lásd a job riportot a "3-tier architekturális
döntés blokkolja" megjegyzésért. Ez a dokumentum a célállapot alakját írja
le, hogy egy jövőbeli job ezekre az itt már megalapozott invariánsokra
implementálhassa.
