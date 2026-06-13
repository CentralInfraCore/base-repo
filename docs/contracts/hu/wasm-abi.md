# WASM ABI szerződés

Ez a dokumentum a guest <-> host WASM ABI önálló referenciája (KB `c689`).
Egy modul implementálásának tutorialjáért lásd a
**[WASM modul-fejlesztési útmutatót](../../hu/wasm-module-authoring.md)**.

## ABI verzió

A `project.yaml` `abi:` blokkja a géppel olvasható manifeszt:

```yaml
abi:
  name: wasm-module-template
  version: "1.0.0"
  envelopeVersion: 1
  exports:
    - allocate
    - deallocate
    - Call
  operations:
    - init
    - process
    - get
    - notify
```

A `module/abi_manifest_test.go` (`TestABIManifestExportsPresent`, amit a
`make wasm.test` futtat) ellenőrzi, hogy az `abi.exports`-ban felsorolt
minden név valóban exportált a lefordított `module/module.wasm`-ban — egy
hiányzó export elbuktatja a buildet.

## Kötelező WASM exportok

A relay host (`CIC-Relay/core/cabinet/cicwasm.go:243-247`,
`newCicWasmHost`) pontosan három exportált függvényt vár el a guest
modultól:

| Export | Szignatúra | Cél |
|---|---|---|
| `allocate` | `(size uint32) -> uintptr` | `size` bájt allokálása a guest lineáris memóriájában; a visszatérési érték az a pointer, ahová a host `Memory().Write`-olhat. |
| `deallocate` | `(ptr uintptr, size uint32)` | Az `allocate` által korábban visszaadott terület felszabadítása. |
| `Call` | `(opPtr, opLen, authPtr, authLen, dataPtr, dataLen uint32) -> uint64` | Egy op végrehajtása. A visszatérési érték egy becsomagolt `(size << 32) \| pointer` eredmény (lásd [envelope.md](envelope.md)). |

Ezeket a `module/abi.go` implementálja, és modulszerzők **nem
módosíthatják** — ez iSDK boilerplate.

A TinyGo `wasip1` target néhány járulékos függvényt is exportál (`memory`,
`malloc`, `free`, `calloc`, `realloc`, `_start`). Ezek nem részei az iSDK
szerződésnek, és nincsenek az `abi.exports`-ban deklarálva — a host soha nem
hívja őket közvetlenül (a guest modulok könyvtárak, nem alkalmazások; a
`_start` sosem kerül meghívásra, lásd `cicwasm.go:177-178`).

## Műveletek (`op` stringek)

A `Call` `op` argumentuma egy domain handlert választ ki
(`module/handlers.go`), amit a `module/abi.go` diszpécsel:

| op | Handler | Megjegyzés |
|---|---|---|
| `init` | `Init(auth, data) ([]byte, error)` | Modul bring-up / konfiguráció. |
| `process` | `Process(auth, data) ([]byte, error)` | A modul fő művelete. |
| `get` | `Get(auth, data) ([]byte, error)` | Idempotens olvasás. |
| `notify` | `Notify(auth, data) ([]byte, error)` | Opcionális v1 stub. |

Minden más `op` string (beleértve az üres `""` stringet is) a
`abi.go` diszpécserénél `CodeInput` hibaborítékkal elutasításra kerül — lásd
[envelope.md](envelope.md) — anélkül, hogy a `handlers.go`-t elérné
(`module/abi_negative_test.go`: `TestHostLoadUnknownOp`,
`TestHostLoadEmptyOp`).

## v1 végrehajtási modell

- **Szinkron**: egy `Call` = egy op, nincs aszinkron callback.
- **Determinisztikus**: nincsenek goroutine-ok, nincs wall-clock-függő
  viselkedés.
- **WASI-off**: a guest kódból nincs fájlrendszer- vagy hálózati hozzáférés
  (a WASI snapshot csak azért van instanciálva, mert a TinyGo `wasip1` target
  ezt linkidőben megköveteli — ez nem szankcionált képesség a modulkód
  számára).

## Memóriatulajdonlás

Az `op`, `auth` és `data` buffereket a host írja a guest memóriájába
(`Memory().Write`) a `Call` előtt, az *eredmény* buffert pedig a guest
allokálja (az `allocate`-en keresztül, a `Call`/`pack` belsejében), majd a
host szabadítja fel (`Memory().Read`, majd `deallocate`) utána. A teljes
sorrendért és a memóriahatár-szerződésért lásd
[host-expectations.md](host-expectations.md).
