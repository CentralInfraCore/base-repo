# WASM guest modul írása

Ez a sablon a CIC iSDK guest modul boilerplate-jét adja: egy kis, TinyGo-val
fordított WASM binárist, amelyet a relay host (`CIC-Relay/core/cabinet`)
[wazero](https://wazero.io) segítségével tölt be, és a `Call` ABI-n keresztül
vezérel.

## Hova írj kódot

| Fájl | Szerkeszthető? | Szerepe |
|---|---|---|
| `module/abi.go` | **Nem** | iSDK boilerplate. Megvalósítja a host által kötelezően elvárt ABI-t (`allocate`, `deallocate`, `Call`), és op-stringre dispatchel a handlerekhez. |
| `module/handlers.go` | **Igen** | A modul domain-logikája. Itt implementálod az `Init`, `Process`, `Get`, `Notify` függvényeket. |
| `module/module_loadtest_test.go` | Általában nem | Host-load smoke test (`make wasm.test`) — bővítsd, ha a modulodnak további round-trip lefedettség kell. |

Minden, amit implementálnod kell, a `handlers.go`-ban van:

```go
//go:build wasip1

package main

func Init(auth, data []byte) ([]byte, error)    { /* bring-up/config */ return nil, nil }
func Process(auth, data []byte) ([]byte, error) { /* fő művelet */ return nil, nil }
func Get(auth, data []byte) ([]byte, error)     { /* idempotens olvasás */ return []byte(`{"status":"ok"}`), nil }
func Notify(auth, data []byte) ([]byte, error)  { /* v1 stub */ return nil, nil }
```

Ha az alapértelmezett `RUNTIME` helyett konkrét hibakódot akarsz visszaadni,
adj vissza `*GuestError`-t a `NewGuestError`-rel (`module/envelope.go`):

```go
func Get(auth, data []byte) ([]byte, error) {
	if len(data) > 0 && !json.Valid(data) {
		return nil, NewGuestError(CodeInput, "data must be valid JSON")
	}
	return []byte(`{"status":"ok"}`), nil
}
```

## A contract (iSDK v1, KB `c689`)

Minden handler két JSON byte-slice-t kap — `auth` (az auth/context objektum)
és `data` (az op input payload-ja) —, és `(dataJSON, error)`-t ad vissza:

- Siker esetén add vissza a `data` JSON payload-ot (vagy `nil`-t, ha nincs
  eredmény), és `nil` hibát.
- Hiba esetén egy nem-nil `error`-t adj vissza:
  - Egy sima `error` (pl. `fmt.Errorf`) az `abi.go`-ban így csomagolódik be:
    `{"data":null,"error":{"code":"RUNTIME","message":"..."}}` — ez az
    alapértelmezett kód a váratlan/belső hibákra.
  - Konkrét kód jelzéséhez adj vissza `*GuestError`-t a
    `NewGuestError(code, message)` hívással (`module/envelope.go`). Az
    `abi.go` ezt kicsomagolja, és a `RUNTIME` alapérték helyett a megadott
    `code`-ot használja.
- `op` ∈ `{init, process, get, notify}`. Ismeretlen op esetén
  `{"error":{"code":"INPUT", ...}}` érkezik — ez a `handlers.go`-ba sosem jut el.
- Hibakódok (`module/envelope.go`: `CodeInput`, `CodeRuntime`, `CodeInternal`,
  `CodeResource`, `CodeTimeout`): `INPUT | RUNTIME | INTERNAL | RESOURCE |
  TIMEOUT`. `INPUT` a hibás caller-adatra (pl. nem parse-olható JSON),
  `RESOURCE`/`TIMEOUT` a környezeti hibákra, `INTERNAL` a bugokra — lásd a
  `Get`-et a `handlers.go`-ban egy `CodeInput` példáért.
- A v1 **szinkron, determinisztikus, WASI-off**: nincs goroutine, nincs
  hálózat, nincs fájlrendszer, nincs valós-idő-függő viselkedés. A `notify`
  v1-ben opcionális stub.

A host minden választ `{data, error}` envelope-ba csomagol
(`CIC-Relay/core/cabinet/cicwasm.go:346`) — ezt az `abi.go` elvégzi
(`marshalData` / `marshalErr`). Neked csak a belső `data` payload-ot kell
előállítanod.

## Build és teszt

A toolchain (TinyGo, Go, wazero) a `builder` konténerben él — a hoston nincs
telepítési lépés.

```sh
make up              # builder konténer indítása
make wasm.build      # TinyGo build -> module/module.wasm, kitölti a project.yaml metadata.buildHash mezőjét
make wasm.test       # module.wasm host-load wazero-val, Call("get", "{}", "{}")
```

A `make wasm.build` a következőt futtatja:

```
tinygo build -o module.wasm -target wasip1 -scheduler=none .
```

a `module/`-ban, majd kiszámolja a `sha256(module.wasm)`-ot, és beírja a
`project.yaml` `metadata.buildHash` mezőjébe (`mk/wasm.mk`,
`tools/compiler.py set-build-hash`).

A `make wasm.test` a `module/module_loadtest_test.go`-t futtatja, amely:

1. betölti a `module.wasm`-ot wazero + `wasi_snapshot_preview1`-tel
   (nincs `_start` — a guest modulok library-k, nem appok);
2. ellenőrzi, hogy a modul exportálja a `Call`, `allocate`, `deallocate`
   függvényeket (`CIC-Relay/core/cabinet/cicwasm.go:243-247`);
3. meghívja a `Call("get", "{}", "{}")`-t, és dekódolja a `{data, error}`
   envelope-ot.

Ha a `module.wasm` még nem létezik, a teszt skip-elve fut, a `make
wasm.build`-re mutató üzenettel.

## Reprodukálható build ellenőrzés

A `make wasm.rebuild-verify` újraépíti a guest modult egy ideiglenes helyre
(a builder konténer `/tmp` mappájába — a commitolt `module/module.wasm`-ot
sosem írja felül), kiszámolja a sha256-ját, és összeveti a `project.yaml`
`metadata.buildHash` mezőjével. Eltérés esetén vagy a commitolt
`module.wasm` elavult (valaki módosította a `module/`-t `make wasm.build`
futtatása nélkül), vagy a TinyGo build nem reprodukálható ebben a
környezetben — mindkét esetben a parancs nem-nulla exit kóddal hibázik, és a
`make wasm.build` futtatására hívja fel a figyelmet a két fájl frissítéséhez.
Ez a CI-ban közvetlenül a `wasm.build` után fut (`.github/workflows/ci.yml`).

## Go quality gate

A `mk/golang.mk` a `module/`-ra van bekötve (`GO_MODULE_DIR=module`):

```sh
make golang.quality   # gofmt -s, staticcheck, go vet, govulncheck a module/-ra
```

Ez a CI-ban a `wasm.build` / `wasm.test` mellett fut
(`.github/workflows/ci.yml`).

## Release / signing

A `make release VERSION=x.y.z` a szabványos háromfázisú release-t futtatja
(`tools/infra.py`, a schemas sablonból öröklve):

1. **Prepare** — checksum-olja a forrás-spec-et, létrehozza a release branch-et.
2. **Build-rés** — itt futtatod a `make wasm.build`-et; ez kitölti a
   `metadata.buildHash`-t.
3. **Finalize** — a `_validate_final_project_yaml` mostantól *megköveteli*,
   hogy a `metadata.buildHash` nem-üres legyen, és a
   `_resign_with_build_hash` újra aláírja a `project.yaml` metadata-ját, így
   a Vault-aláírás egyszerre fedi a forrás-spec checksumot *és* a bináris
   hash-t — egyetlen aláírás, amely a provenance-t és az integritást egyben
   köti.
