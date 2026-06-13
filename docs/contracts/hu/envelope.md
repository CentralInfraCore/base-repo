# JSON envelope szerződés

Ez a dokumentum a minden `Call` által visszaadott `{data, error}` JSON
envelope önálló referenciája (KB `c689`). Lásd még
[wasm-abi.md](wasm-abi.md) a körülötte lévő ABI-ért.

## Alak

Minden `Call` egy JSON objektumot ad vissza, pontosan két top-level kulccsal:

```json
{"data": <bármilyen JSON érték> | null, "error": <GuestError> | null}
```

A `data` / `error` közül pontosan egy nem null:

- **Siker**: a `data` a handler JSON payloadja (vagy `null` egy üres
  eredmény esetén — lásd a "null-success" esetet alább), az `error`
  `null`.
- **Hiba**: a `data` `null`, az `error` egy `GuestError` objektum.

```go
// module/envelope.go
type guestResult struct {
    Data  json.RawMessage `json:"data"`
    Error json.RawMessage `json:"error"`
}
```

Ez megfelel a host `GuestResult` struktúrájának
(`CIC-Relay/core/cabinet/cicwasm.go:346`).

## `GuestError` alak

```json
{"code": "INPUT", "message": "ember által olvasható leírás"}
```

```go
// module/envelope.go
type guestError struct {
    Code    string `json:"code"`
    Message string `json:"message"`
}
```

## Hibakódok

A `module/envelope.go`-ban definiálva, a KB `c689` szerint:

| Kód | Jelentés | Tipikus forrás |
|---|---|---|
| `INPUT` | Hibás hívói adat (pl. érvénytelen JSON, ismeretlen/üres `op`). | `handlers.go` a `NewGuestError(CodeInput, ...)` -on keresztül, vagy az `abi.go` diszpécsere ismeretlen `op` esetén. |
| `RUNTIME` | Váratlan/belső hiba. **Alapértelmezett** egy handlerből visszaadott egyszerű (nem típusos) `error` esetén. | `abi.go`'s `Call`, amely minden nem-`*GuestError`-t becsomagol. |
| `INTERNAL` | A handler olyan kimenetet produkált, ami nem érvényes JSON. | `marshalData` (`envelope.go`) — egy védő fallback, hogy hibás JSON soha ne jusson el a hosthoz. |
| `RESOURCE` | Környezeti szintű erőforrás-kimerülés. | Handler-specifikus, a `NewGuestError(CodeResource, ...)`-on keresztül. |
| `TIMEOUT` | A művelet túllépte az időkeretét. | Handler-specifikus, a `NewGuestError(CodeTimeout, ...)`-on keresztül; a *host* is produkál egy `TIMEOUT` envelope-ot `cicwasm.go` szinten `context.DeadlineExceeded` esetén, de más envelope alakkal — lásd [host-expectations.md](host-expectations.md). |

Egy adott kód jelzéséhez a handler `*GuestError`-t ad vissza a
`NewGuestError(code, message)`-on keresztül. Egy egyszerű `error` (pl.
`fmt.Errorf(...)`) mindig `CodeRuntime`-ként van becsomagolva az `abi.go`
`Call`-ja által.

## Null-success szerződés

A template `init`, `process` és `notify` stubjai (`module/handlers.go`)
`(nil, nil)`-t adnak vissza. A `marshalData(nil)`-nak ezt kell produkálnia:

```json
{"data": null, "error": null}
```

azaz egy **jelen lévő, nem-üres envelope-ot**, amelynek `data` mezője a
`null` JSON literál — nem egy üres/zéró eredmény. Ezt ellenőrzi a
`module/module_loadtest_test.go` `TestHostLoadNullSuccess` (payload `"{}"`)
és a `module/abi_negative_test.go` `TestHostLoadEmptyPayloadNullSuccess`
(payload `""`) tesztje.

Ez különbözik az alábbi **packed-zero** esettől, amit a guest soha nem
produkálhat egy `{data,error}` eredményhez.

## Wire transport: pack/unpack

A `Call` nem közvetlenül az envelope bájtjait adja vissza — egy darab
`uint64`-et ad vissza:

```go
// module/abi.go
func pack(b []byte) uint64 {
    if len(b) == 0 {
        return 0 // a host a packed 0-t null/empty-ként kezeli (cicwasm.go:337-339)
    }
    ptr := allocate(uint32(len(b)))
    copy(unsafe.Slice((*byte)(unsafe.Pointer(ptr)), len(b)), b)
    return (uint64(uint32(len(b))) << 32) | uint64(ptr)
}
```

- Felső 32 bit: az eredmény hossza.
- Alsó 32 bit: pointer a guest lineáris memóriájába (az `allocate` allokálja,
  a host a `deallocate`-en keresztül szabadítja fel olvasás után).
- A `0` becsomagolt érték (`ptr=0, len=0`) host-oldali rövidítés
  `data="null", error="null"`-ra (`cicwasm.go:337-339`) — de a `marshalData`
  / `marshalErr` mindig nem-üres `{"data":...,"error":...}` bájtsorozatot
  produkál, így a guest `Call`-ja a gyakorlatban soha nem ad vissza
  legitim módon packed `0`-t. A `module/module_loadtest_test.go` `callOp`
  helpere ezért egy packed `0` eredményt teszthibaként kezel.

## Verziózás

A `project.yaml` `abi.envelopeVersion` mezője (jelenleg `1`) azonosítja ezt
az envelope alakot. Egy jövőbeli, az `{data, error}` struktúrát érintő
breaking change (pl. új kötelező mezők hozzáadása, hibakód-szemantika
változása) köteles az `envelopeVersion`-t emelni és ezt a dokumentumot
frissíteni.
