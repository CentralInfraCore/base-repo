# KB storage and indexing architecture — proposal for issue #52

Status: **proposal / evaluation candidate; not an approved design**  
Date: 2026-11-23  
Related incident: [CentralInfraCore/base-repo#52](https://github.com/CentralInfraCore/base-repo/issues/52)  
Implementation reviewed: `CentralInfraCore/cic-mcp-private` (`mcp-server/kb_watch.py`, `mcp-server/server.py`, `make_source.py`), default branch as inspected 2026-11-23.

## Decision framing

Issue #52 is an incident/measurement record, not a design decision. This document proposes a **logical architecture** and a staged evaluation. Neither the technology selection nor expected memory/search improvements are proven without a representative benchmark.

**Recommended first candidate:** PostgreSQL (canonical state, graph and transactional outbox) + Qdrant (rebuildable lexical/vector search projection) + optional NATS JetStream (durable work distribution) + optional S3-compatible object storage (content-addressed artifacts and evidence). A multi-service deployment is acceptable; **the consistency contract matters more than service count**.

The design principle is **one canonical source of truth, multiple independently rebuildable projections**. Search indexes are not authoritative state.

## Verified implementation constraints and issues

- `kb_watch.py::incremental_update` re-embeds changed chunks but loads complete `chunks.pkl` and `embeddings_by_id.pkl`, rebuilds FAISS `IndexFlatIP` from a stacked full vector matrix, and recomputes BM25/inverted indexes over all chunks.
- `kb_watch.py::_dump_pkl` in the inspected `cic-mcp-private` default branch calls `Path.write_bytes(pickle.dumps(obj))` directly. **This path is not an atomic tempfile+rename write.** The #52 issue's statement about atomic PKL writes needs validation against the exact deployed revision. FAISS is also written directly by `faiss.write_index(..., path)` in that inspected function.
- The MCP `server.py::search_query` uses FAISS when available and BM25/inverted as a fallback; it does **not** currently fuse both result sets. Native hybrid retrieval is a possible functional improvement, not guaranteed result parity.
- `server.py` exposes more than retrieval: lexical/code search, chunk and node lookups, metadata filters, graph traversals, `focus_pack`, impact analysis, guided navigation, and writable task/companion/decision operations. A search-engine replacement alone is not feature-complete.
- Existing `make_source.py::save_kb_to_sqlite` exports relational subsets; it is a migration aid, **not** an already functioning replacement for the MCP backend.
- Issue #52 measured approximately 617 MB PKL bytes expanding to ~2.97 GB loaded, with ~4.1–4.4 GB resident live watchers and an 11.5 GB orphan process. Peak rebuild RSS, model footprint, and root-cause attribution of the host OOM remain unmeasured. Do not treat summed per-process RSS as unique host RAM.
- Historical process duplication/orphaning was also recorded in the factory thread from 2026-10-23; collect process-supervision evidence as a separate workstream.

## Logical components

```text
Git / Markdown / YAML / source code
           |
           v
  source scanner + content-hash / provenance
           |
           v
  transactional canonical store (PostgreSQL)
    sources, versions, chunks, nodes, edges,
    metadata, generation state, outbox
           |                          \
           |                           -> immutable artifacts/evidence (S3, optional)
           v
  work dispatcher (DB outbox worker; optional NATS JetStream)
           |
           +-- chunking / embedding workers
           +-- search projection builder (Qdrant)
           +-- graph projection builder (optional dedicated graph engine)
           +-- projection verifier
           |
           v
  generation publication barrier
           |
           v
  read-only retrieval facade -> existing MCP tool contracts
  (hybrid search, graph traversal, focus_pack, impact_analysis)
```

### Component responsibilities and boundaries

| Component | Responsibility | Not responsible for |
| --- | --- | --- |
| PostgreSQL | Canonical sources/chunks/nodes/edges; stable IDs; source hashes; generation FSM; relational constraints; outbox; publication pointer | ANN search engine implementation |
| Qdrant | Rebuildable dense+sparse/BM25 search, metadata payload filters, ranking/fusion; generation-scoped collection/alias or payload | Canonical state, authoritative graph, release publication |
| NATS JetStream (conditional) | Retryable, observable, replayable distribution of derived-index work; consumers are idempotent | Cross-database atomic transactions or canonical event truth |
| S3-compatible store (conditional) | Content-addressed input/output blobs, model/index manifests, immutable evidence; retention/versioning if configured | Search or referential integrity |
| MCP facade | Existing public tool contract, retrieval orchestration, explicit generation selection and provenance in results | Mutating derived stores directly |

**Start without NATS** when a PostgreSQL transactional outbox + worker meets throughput and recovery targets. Add JetStream if independent worker classes, backpressure and replay warrant the added service. **Start without S3** when content-addressed files on a controlled filesystem meet audit and disaster recovery requirements. "S3-compatible" does not automatically imply WORM; enable and test versioning/object lock where needed.

### Graph engine decision

Start with PostgreSQL edge tables and recursive SQL for current node/edge/adjacency queries. Benchmark Neo4j/Memgraph only for graph workloads that demonstrably exceed acceptable complexity or latency (deep multi-hop traversal, sophisticated path queries, dependency/proof propagation). Avoid duplicating an authoritative graph in an independently writable graph DB.

### Alternative search backends

- **Qdrant:** preferred first benchmark; dense/sparse/BM25 and fusion, per-point updates, filtered retrieval. Verify generation isolation, consistency, model/tokenizer choices, RAM/SSD tuning and operational recovery.
- **Vespa / OpenSearch:** parallel shortlist for advanced ranking, lexical semantics and higher-scale retrieval; evaluate operational footprint and exact requirements instead of assuming superiority.
- **SQLite FTS5 + sqlite-vec:** compact single-host baseline; strong transaction and low-infrastructure alternative, especially valuable for objective RSS and parity measurements.
- **LanceDB:** MVCC/versioned dataset candidate; assess transaction/version semantics and graph adaptation against the same tests.
- **Tantivy + FAISS:** possible custom Rust-heavy build but carries more integration and maintenance responsibility.

Do not equate FAISS `IndexFlatIP`'s exact inner-product ranking with approximate ANN behavior. Compare exact-mode first; measure recall and latency when introducing approximate indexes.

## Generations and consistent reads

A PostgreSQL commit does **not** make Qdrant and an external graph index atomically consistent. Enforce generation-scoped publication explicitly:

1. Commit the source change, source hash, immutable chunk identity and `generation=G` in PostgreSQL. Add outbox record in the **same PostgreSQL transaction**.
2. Dispatch workers. Every task has stable event ID + generation + content hash; handle at-least-once delivery by idempotent writes and duplicate suppression.
3. Build/validate the complete search and graph projections for G, isolated from the active generation; record projection checksums, counts, model/config version and read-test evidence.
4. Record verified readiness for **all required projections**. Only then commit `active_generation=G` in PostgreSQL. On failure, retain G-1.
5. MCP pins one active generation at request start. Every projection read must be scoped to that generation; retain G-1 (and any pinned generation) until readers drain or expire. Alias swap alone is insufficient unless in-flight queries are pinned and old indexes remain accessible.
6. Record `generation_id`, source manifest digest, model ID/version, index config/digest, retrieval parameters and evidence reference with each retrieved context when an audit is required.

Prefer build-then-publish over direct in-place mutation of the currently active search collection. If using in-place incremental updates for low latency, define and test a separate read-consistency strategy (generation-tagged points/filtered reads, tombstones, and GC). The system must reject missing or mixed-generation reads, rather than silently returning inconsistent context.

### Candidate state model

```text
PREPARING -> INDEXING -> VERIFYING -> READY -> ACTIVE -> RETAINED -> GC
      \         \          \
       FAILED <-- FAILED <-- FAILED
```

A generation manifest should minimally capture: source snapshot digest, parser/chunker version, embedding model + revision, per-chunk stable IDs/hashes, projection schema/config versions, index artifact references, validation results, and publication timestamps.

## Functional compatibility requirements

Preserve the existing MCP operations and semantics where feasible:
- `search_query`, `search_token`, `search_code`: lexical/dense retrieval and rankings (record intentional changes).
- `get_chunk`, `get_node`, `search_nodes`, `find_nodes`, `resolve_path`: stable references and filters.
- `neighbors`, `impact_analysis`, `guided_path`, `explain_node`, `focus_pack`: graph expansion, rules/CONTRACT/DoD/LIMITS prioritization, reading order.
- `kb_status`, `reload_kb`: generation-aware health and reload semantics.
- Task lifecycle, companion YAML updates and decisions: preserve authorization, durable writes and clear ownership. They **must not** be smuggled into a read-only Qdrant index as authoritative state.

Review current `make_source.py` chunking, deduplication, path/line-range provenance, YAML companion metadata, multilingual code/token handling and graph edges. Generic embedding databases do not automatically reproduce these CIC-specific semantics.

## Evaluation plan (evidence before adoption)

### P0 — stabilize and measure (independent of DB choice)
- Enforce single-writer ownership or lock for the shared legacy KB directory, stop orphaned watch processes, establish systemd/process ownership and shutdown/reap semantics.
- Verify exact deployed revision of atomic file-write behavior; prevent partial/mixed multi-file snapshots.
- Capture peak **RSS/PSS**, private dirty memory, swap, CPU, write amplification, rebuild duration, and host-level memory pressure across repeated change batches.
- Count actual chunks, distinct terms, vectors, vector dimensions, graph nodes/edges, query mix and write rate.

### P1 — representative fixtures and golden retrieval tests
- Freeze current source snapshot and embedding model. Preserve canonical legacy FAISS results, lexical results, graph traversals, metadata, context packs and mutation-tool outcomes.
- Include exact symbol and path queries, multilingual natural language, adversarial duplicates, document deletion/rename, concurrent updates and interrupted writes.
- Set tolerances for ranking metrics (Recall@10, nDCG@10), exact IDs/line ranges, and graph/contract parity. Different tokenizers/BM25 implementations need explicit approved differences.

### P2 — side-by-side backend spikes
- Candidate A: PostgreSQL + Qdrant (without optional NATS/S3 initially).
- Candidate B: SQLite FTS5 + sqlite-vec (resource/transaction baseline).
- Candidate C: LanceDB or Vespa/OpenSearch (based on measured ranking needs).
- Run identical data, query set and concurrency. Report aggregate *system* RSS/PSS, idle and peak memory, swap, p50/p95/p99 latency, update and recovery times, disk footprint, recall/relevance, consistency, service complexity.
- Shadow MCP traffic first; no cut-over until acceptance gates pass.

### P3 — distributed correctness and rollout
- Add transactional outbox; introduce JetStream only if measured benefits justify it. Introduce S3 artifacts when provenance/retention/rebuild requirements justify it.
- Fault-inject worker crash, broker outage, duplicate/out-of-order delivery, DB failover, collection build failure, partial projection and rollback.
- Prove zero mixed-generation responses under concurrent publish/read, and exact recovery to the last valid active generation.
- Roll out with feature flag/dual-read, rollback plan and observation of total host resource pressure.

## Proposed acceptance gates (quantitative targets to set from baseline)

1. **Zero** mixed-generation MCP responses in fault-injection and concurrent-load tests.
2. **Zero** lost committed source changes, with documented replay/recovery and idempotency.
3. All existing MCP tool contracts pass compatibility tests, including write tools.
4. Search relevance meets approved exact-match and recall/ranking thresholds relative to the captured baseline.
5. Measured total service memory and peak update RAM are below a chosen host budget with reserve; no OOM/swap exhaustion.
6. Recovery, incremental-update latency, operational overhead and index rebuild time satisfy explicit SLOs.
7. Manifest/evidence identifies precisely the source snapshot and model/index generation used per returned context.
8. System remains correct after crash/restart, deletion, concurrent updates and rollback.

## Open decisions

- Is `source_version` a Git commit, a content-addressed snapshot, or both?
- Do MCP clients need strict latest-state reads, pinned snapshot reads, or both?
- Are task/decision writes part of the same canonical database or external Git-managed workflows?
- What retention and legal/audit immutability requirements apply to source and evidence blobs?
- What are acceptable freshness, read latency, memory ceiling, corpus growth and replay duration?
- What actual graph queries (depth/fan-out/path predicates) require a dedicated graph database?
- Can embedding inference run as a singleton service to avoid per-session model duplication?

## Non-goals

- This proposal does not authorize implementation, migration or changing the original incident measurements.
- It does not assert that PostgreSQL + Qdrant is already benchmark-proven best.
- It does not claim that a distributed collection alias or PostgreSQL alone solves cross-service consistency.
- It does not propose deleting the legacy PKLs until full parity, recovery and rollback have been demonstrated.

## Documentation links

- PostgreSQL transactions: https://www.postgresql.org/docs/current/tutorial-transactions.html
- PostgreSQL recursive queries: https://www.postgresql.org/docs/current/queries-with.html
- Qdrant hybrid queries: https://qdrant.tech/documentation/search/hybrid-queries/
- Qdrant index management: https://qdrant.tech/documentation/manage-data/indexing/
- NATS JetStream: https://docs.nats.io/nats-concepts/jetstream
- S3 Object Lock (AWS example): https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html
- SQLite FTS5: https://www.sqlite.org/fts5.html
- sqlite-vec: https://github.com/asg017/sqlite-vec
- LanceDB: https://lancedb.github.io/lancedb/
