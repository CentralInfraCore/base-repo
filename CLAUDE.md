# CLAUDE.md — CentralInfraCore MCP Base

## Mi ez a repo?

Ez a **CentralInfraCore MCP base template** — egy alap Git repo amit git remote merge-vel raknak rá más CIC-ből származó repokra. Nem önálló termék, hanem template: a belőle levont repok öröklik az MCP szerver infrastruktúráját, a build tooling-ot és a release folyamatot.

## MCP szerver

A repo egy FastMCP-alapú knowledge base szervert tartalmaz, ami a `source/` könyvtár tartalmából épít kereshető tudásgráfot.

```
source/          ← ide kerülnek a repo docs + a CIC ökoszisztéma repo-k
    ↓
make kb.build    ← make_source.py: TF-IDF + cosine similarity gráf
    ↓
kb_data/pkl/     ← generált pickle fájlok (gitignore-d)
    ↓
make mcp.run     ← mcp-server/server.py (FastMCP, stdio)
```

## Kulcs parancsok

```bash
make mcp.config     # .mcp.json generálás (első lépés, repo clone után!)
make kb.build       # Knowledge base generálás a source/ tartalmából
make mcp.run        # MCP szerver indítás (stdio, Claude Code-hoz)
make mcp.run.sse    # MCP szerver indítás (SSE/HTTP)

make up             # Docker dev környezet (release tooling-hoz)
make validate       # Schema validáció
make release-check VERSION=x.y.z
make release-prepare VERSION=x.y.z
make release-close VERSION=x.y.z
```

## Könyvtár struktúra

```
make_source.py        ← KB generátor
mcp-server/server.py  ← FastMCP szerver (12 tool)
source/               ← forrás docs (gitkeep, a fogadó repo tölti fel)
kb_data/              ← generált KB (pkl/, json/ — gitignore-d)
sqlite_data/          ← generált SQLite (gitignore-d)
schemas.json          ← adat struktúra sémák
sqlite_data/db_schema.json ← SQLite tábla definíciók
.mcp.json             ← MCP szerver konfiguráció Claude Code-hoz
p_venv/               ← Python venv (gitignore-d)

tools/                ← release tooling (compiler.py, infra.py, vault signing)
docs/                 ← architektúra és koncept dokumentáció (EN + HU)
features/             ← feature specifikációk
mk/infra.mk           ← Makefile implementáció
```

## Python környezet

Az MCP szerver és a KB generátor a lokális `p_venv/`-et használja (nem Docker):
```bash
p_venv/bin/python make_source.py
p_venv/bin/python mcp-server/server.py
```

A release tooling (validate, test, fmt) Docker containerben fut.

## MCP szerver tool-ok

| Tool | Leírás |
|------|--------|
| `search_query` | Multi-token keresés TF-IDF invertált indexen |
| `search_token` | Single token lookup |
| `search_code` | Substring keresés chunk tartalomban |
| `search_nodes` | Node keresés név/label/tag alapján |
| `resolve_path` | Chunk keresés fájlút alapján |
| `get_chunk` | Chunk lekérés ID alapján |
| `get_node` | Node lekérés ID alapján |
| `neighbors` | Graph szomszédok lekérése |
| `focus_pack` | Kontextus csomag (rule prioritizálással) |
| `explain_node` | Node mély elemzése |
| `kb_status` | KB állapot és fájl info |
| `reload_kb` | KB újratöltés lemezről |

## Repo konvenciók

- Branch naming: `{component}/releases/v{VERSION}` (release), `mcp/devel` (MCP fejlesztés)
- Tag format: `{component}@v{VERSION}`
- Commit signing: Vault Transit engine (git hook)
- `project.yaml`: minden release metaadatot és kriptográfiai aláírást tartalmaz
- `md.meta.schema.yaml`: dokumentáció metadata sémája (tags, categories, used_in)

## Kapcsolódó rendszerek

- **CIC-Relay**: Go-alapú control plane (Nexus orchestrator, WASM)
- **CIC-Schemas**: Schema compiler és Vault signing
- **CIC-Registry**: 3-rétegű registry (schemas/mods/agents)
- **HashiCorp Vault**: Transit signing, KV v2 cert storage
