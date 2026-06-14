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

## project.yaml séma: abi: blokk és provenance metaadatok

A `project.schema.yaml` modellezi a `project.yaml` tényleges top-level és
`metadata`/`compiler_settings` kulcsait (`tags`, `validatedBy`, `createdBy`,
`build_timestamp`, `validity`, `checksum`, `sign`, `buildHash`, `cicSign`,
`cicSignedCA` is), `additionalProperties: false`-szal a `metadata`,
`compiler_settings` és `abi` blokkokon. Az `abi:` blokknak saját sémája van,
`abi.schema.yaml`, amire a `project.schema.yaml` `$ref`-fel hivatkozik.

Az `abi.schema.yaml` JSON szintaxisban íródott (ami a YAML egy érvényes
részhalmaza): a jsonref alapértelmezett loader-e (amit a
`tools.infra.load_and_resolve_schema` használ) csak JSON dokumentumra mutató
`$ref`-eket old fel, YAML block szintaxist nem — ld. `tools/infra.py:73-87`.
A hivatkozott fájl JSON-in-`.yaml`-ként írása egyetlen forrást ad az `abi:`
alaknak a `tools/infra.py` módosítása nélkül.

A TBD placeholder mezők (`createdBy`, `cicSign`, `validatedBy.checksum`,
`checksum`, `sign`, `cicSignedCA`) `string`/`object` típusúak maradnak,
formátum-megkötés nélkül, így egy template/unreleased `project.yaml`
séma-valid marad — ld. a `project.schema.yaml` mező-szintű `description`-jeit
arról, mit jelent egyenként a placeholder és melyik job tölti ki.

## verify-release: offline release-készenléti ellenőrzés

**Implemented** (ez a job). A `make verify-release`
(`tools/verify_release.py`, `Makefile` `verify-release` target) egyetlen
offline futtatással ellenőrzi:

1. a `project.yaml` validálódik a `project.schema.yaml` ellen (az `abi:`-t
   is, az `abi.schema.yaml`-on keresztül);
2. a `module/module.wasm` sha256-a megegyezik a `project.yaml`
   `metadata.buildHash`-ével, a `make wasm.rebuild-verify`-jal (`mk/wasm.mk`)
   azonos TinyGo-hívással egy scratch helyre újraépítve;
3. a `project.yaml` `abi.exports`-a megegyezik a `module/module.wasm`
   tényleges exportjaival, a `module/abi_manifest_test.go`
   `TestHostLoadABIManifestExportsPresent`-jének (`go test`) futtatásával;
4. a `MANIFEST.sha256` megegyezik a working tree-vel (mint a `make
   manifest-verify`);
5. a provenance mezők (`createdBy`, `validatedBy.checksum`, `checksum`,
   `sign`, `cicSign`, `cicSignedCA.certificate`) státusza
   `OK` / `TBD` / `MISSING`-ként jelentve.

Az 1-4. pont az exit kódot is meghatározza (nem-nulla, ha bármelyik `FAIL`);
az 5. pont **csak informatív**.

### Amit a `verify-release` NEM ellenőriz

- **Nincs kriptográfiai aláírás-ellenőrzés.** Az 5. pont csak azt jelenti,
  hogy `createdBy`/`cicSign`/`cicSignedCA`/`sign`/`checksum` jelen van-e,
  `"TBD"`, vagy hiányzik — nem hív Vault-ot és nem ellenőriz semmilyen
  tanúsítványláncot vagy aláírást. A `verify-release` `PASS`-a **nem**
  bizonyítja, hogy a commit egy megbízható CIC kulccsal van aláírva.
- **Nincs `repository_tree_hash`/`signing_metadata` ellenőrzés** (a
  `project.schema.yaml` `release:` blokkja) — azt a `make release` tölti ki,
  ez itt nem hatókör.
- **Nincs hálózati/Vault hozzáférés** — szándékosan, hogy a parancs CI-ban és
  Vault-hitelesítő adatok nélküli fejlesztői gépen is működjön.

Az 5. pont `TBD` eredménye egy template/unreleased `project.yaml`-nál
elvárt, és nem bukik el; a `MISSING` azt jelenti, hogy a metadata kulcs maga
hiányzik a `project.yaml`-ból (séma probléma, ezt az 1. pont is elkapja).

A `verify-release` ebben a jobban **nincs** bekötve a
`.github/workflows/ci.yml`-be: ez egy release-készenységi gate (a `make
release` futtatás előkészítésekor releváns), nem egy minden push-ra futó
ellenőrzés, mint a `wasm.rebuild-verify`/`wasm.test`/`manifest-verify`. Egy
jövőbeli job eldöntheti, hogy/hová kötné be CI step-ként (pl. csak release
branch-eken).
## Célállapot: bizonyítható, aláírt release bundle

Az implementált állapot — `buildHash` + `wasm.rebuild-verify` + ABI
manifeszt + `MANIFEST.sha256` + `project.yaml`/`abi.schema.yaml` séma-validáció
+ `verify-release` — egy adott commitra megalapozza, hogy:

- a `module/module.wasm` pontosan az, amire a `module/*.go` fordul
  (reprodukálható build);
- a `module/module.wasm` exportjai megfelelnek annak, amit a `project.yaml`
  deklarál (ABI manifeszt);
- semmilyen más tracked fájl nem driftelt váratlanul (repository manifeszt);
- a `project.yaml` szerkezete (az `abi:` szerződést is) megfelel a
  dokumentált sémának.

A release **artifact** (egy disztribuálható bundle, szemben egy aláírt
forrás commit-tal) célállapota ezekre az invariánsokra épül: egy
`module/module.wasm` + `project.yaml` + egy Vault-aláírás mindkettő felett
bundle lehetővé tenné egy downstream fogyasztónak, hogy offline ellenőrizze:
(a) a wasm bináris megfelel a deklarált `buildHash`-nek, (b) a deklarált
`abi.exports`/`operations` megfelel a bináris tényleges exportjainak, (c) a
`project.yaml` séma-valid, és (d) a bundle egy megbízható CIC kulccsal van
aláírva — anélkül, hogy a forrásfára vagy egy TinyGo toolchain-re szükség
lenne. A `verify-release` az (a)-(c)-t implementálja; a (d) (a
`cicSign`/`createdBy.certificate` tényleges kriptográfiai ellenőrzése egy CIC
Root CA ellen, Vault hozzáférés nélkül) **TBD** marad — ld. "Amit a
`verify-release` NEM ellenőriz" fent.

Ennek a bundle formátumnak a definiálása, és hogy ez hogyan illeszkedik a
meglévő háromfázisú `tools/infra.py` release folyamathoz, **nem ennek a
jobnak a hatóköre** (3. tier review elem, `wasm-release-pipeline-audit`) —
lásd a job riportot a "blocked by release-pipeline audit" megjegyzésért.
