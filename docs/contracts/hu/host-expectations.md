# Host elvárások szerződés

Ez a dokumentum leírja, hogy a relay host
(`CIC-Relay/core/cabinet/cicwasm.go`) mit csinál minden `Call` körül, és mit
tételezhet fel — vagy mit nem szabad feltételeznie — egy guest modulnak
(ez a template) erről a környezetről. Lásd még [wasm-abi.md](wasm-abi.md) és
[envelope.md](envelope.md).

## Instanciálás

- A host [wazero](https://wazero.io) alatt futtatja a guestet, a
  `wasi_snapshot_preview1` modul instanciálva van (`cicwasm.go:70`), mert a
  TinyGo `wasip1` targetje ezt linkeli — **nem** azért, mert a guest kódnak
  szabad WASI syscallokat hívnia (a v1 WASI-off, lásd
  [wasm-abi.md](wasm-abi.md)).
- A modul `wazero.NewModuleConfig().WithStartFunctions()`-szel van
  instanciálva (`cicwasm.go:178`) — azaz **a `_start` sosem kerül
  meghívásra**. A guest modulok könyvtárak, nem alkalmazások. A
  `module/module_loadtest_test.go` ezt pontosan így másolja le.
- A `newCicWasmHost` (`cicwasm.go:243`) korán elbukik, ha a lefordított modul
  nem exportálja a `Call`, `allocate`, `deallocate` függvényeket — lásd
  [wasm-abi.md](wasm-abi.md#kötelező-wasm-exportok).

## Egy hívás sorrendje (`callGuest`, `cicwasm.go:267-`)

Az `Init` / `Process` / `Get` / `Notify` mindegyikéhez a host:

1. `allocate`-tal allokálja és `Memory().Write`-tal beírja az `op` stringet
   a guest memóriájába.
2. `allocate`-tal allokálja és beírja az `authContextJson`-t.
3. `allocate`-tal allokálja és beírja az `inputJson`-t (data).
4. Meghívja a `Call(opPtr, opLen, authPtr, authLen, dataPtr, dataLen)`-t egy
   hívásonkénti timeout alatt (`WasmManagerConfig.DefaultTimeoutSeconds`).
5. A visszaadott `uint64`-et `(size << 32) | pointer`-ként dekódolja
   ([envelope.md](envelope.md#wire-transport-packunpack)).
6. `Memory().Read`-del kiolvassa az eredmény bájtjait, JSON-dekódolja a
   `{data, error}` envelope-ot.
7. `deallocate`-tal felszabadítja mind a négy buffert (op, auth, data,
   result) — a hibás útvonalakon is (`defer`).

Egy guest modul `Call` implementációja (`module/abi.go`) csak a 4. lépéstől
látja a folyamatot; az 1-3. és 7. lépés host-felelősség, amit egy
modulszerző sosem implementál közvetlenül, de a
`module/module_loadtest_test.go` `callOp`/`writeString` helperei
újraimplementálják a host-load teszthez.

## Memóriahatár-szerződés

- A host csak olyan `ptr`/`len` páreket ad át a `Call`-nak, amelyekhez az azt
  megelőző `Memory().Write` sikeres volt. A `wazero` `Memory().Write` és
  `Memory().Read` `ok=false`-t ad vissza (panic helyett) bármilyen
  tartományon-kívüli hozzáférés esetén — ezt közvetlenül ellenőrzi a
  `module/abi_negative_test.go` `TestHostMemoryOutOfBoundsAccess` tesztje.
- Ha a `writeStringToWasm` sikertelen (pl. allokációs hiba), a `callGuest`
  egy `HOST_ERROR` envelope-ot ad vissza **a `Call` meghívása előtt** — a
  guest sosem lát érvénytelen `ptr`/`len`-t.
- A `module/abi.go` guest-oldali `readBytes`/`readString` függvényeinek
  **nincs önálló bounds-check-je** — a fenti host-invariánsra
  támaszkodnak. Ez szándékos: a guest nem tudja biztonságosan validálni a
  saját lineáris memóriájába mutató pointereket a host által már garantáltnál
  túlmenően, és a TinyGo `unsafe.Slice`-a egy valóban érvénytelen pointeren
  panicolna/trapolna, nem hibát adna vissza. A határ egyszer, a host oldalán
  van kikényszerítve.

## Host-oldali hibaborítékok

A guest által produkált `{data, error}` envelope-on
([envelope.md](envelope.md)) felül a `cicwasm.go` `callGuest`-je maga is
produkálhat egy hibát *a guest hívása előtt* vagy *helyett*, a
`formatErrorJson(code, message, ...)`-on keresztül:

| Kód | Mikor |
|---|---|
| `HOST_ERROR` | Sikertelen volt egy buffer beírása a guest memóriájába, vagy sikertelen volt az eredmény kiolvasása/dekódolása. |
| `TIMEOUT` | `context.DeadlineExceeded`, amíg a `Call` visszatérésére várt. |
| `RUNTIME` | A `Call` maga adott vissza Go `error`-t (pl. egy wazero trap). |

Ezek **host szintű** envelope-ok — különböznek a guest
`{"error":{"code":"TIMEOUT",...}}`-jétől
([envelope.md](envelope.md#hibakódok)). Egy modulszerző nem produkálhat
`HOST_ERROR`-t a `handlers.go`-ból; ez egy host/runtime szintű hibát jelez,
amely sosem érte el a guest diszpécserét.

## Packed-zero eredmény

A `0` becsomagolt eredményt (`ptr=0, len=0`) a host
`data="null", error="null"`-ként kezeli (`cicwasm.go:337-339`) anélkül, hogy
`Memory().Read`-et kísérelne meg. A `module/abi.go` `pack`-je csak egy
nulla-hosszú byte slice esetén ad vissza `0`-t, amit a `marshalData`/
`marshalErr` soha nem produkál — lásd
[envelope.md](envelope.md#wire-transport-packunpack).

## Timeoutok és erőforráskorlátok

- A `WasmManagerConfig.DefaultTimeoutSeconds` korlátoz minden `Call`-t
  `context.WithTimeout`-on keresztül (`cicwasm.go:267`).
- A `WasmManagerConfig.DefaultMemoryPages` és az LRU `compiledModules` cache
  korlátozza a lefordított modulok memóriáját; az eviction lezárja a
  mögöttes `wazero.CompiledModule`-t (`cicwasm.go:96-104`).
- A guest kódnak (v1) nincs mechanizmusa arra, hogy ezeknél a
  host-konfigurált limiteknél több időt vagy memóriát kérjen —
  a `RESOURCE`/`TIMEOUT` `GuestError`-ok
  ([envelope.md](envelope.md#hibakódok)) **handler által észlelt**
  erőforrásproblémákra vannak (pl. egy al-művelet eléri a saját belső
  limitjét), nem a host limitjeinek tárgyalására.
