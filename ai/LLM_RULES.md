# LLM Rules

- A signing formátum (`[signing-metadata]` + `[certificate]` blokk) invariáns — ne módosítsd.
- `project.yaml`-t csak a `compiler_settings` dokumentált mezőivel bővítsd (`project.schema.yaml` a referencia).
- Vault hívásokban `prehashed: true` és `hash_algorithm: sha2-256` — ne változtasd.
- Új fájl létrehozása előtt olvasd fel a könyvtár struktúráját — illeszkedj a konvenciókhoz.
- `make test` zöldnek kell maradnia minden változtatás után.
- Titkokat (token, cert, PAT) soha ne hardcode-olj — mindig env változó vagy bind mount.
- Változtatáskor rövid diff-magyarázatot adj.