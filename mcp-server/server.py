#!/usr/bin/env python3
"""
Graph MCP server for CIC knowledge base stored in PKL files (legacy format supported).

Read-only MCP server that exposes:
- token search via inverted_index.pkl
- chunk/node lookup
- graph traversal (neighbors)
- simple filtering (by tag/category/used_in) if metadata exists in node/chunk payloads
- focus_pack: context gathering with rule prioritization
- explain_node: deep dive into specific nodes
- search_nodes: lookup nodes by name/label/tags
- kb_status: check KB file status
- reload_kb: force-reload the knowledge base

Works with stdio (default) and SSE (HTTP) if you wrap it similarly to your docs_mcp.py.
"""

from __future__ import annotations

import os
import pickle
import re
import argparse
import hashlib
import json
import threading
import time
import numpy as np
import faiss
from pathlib import Path
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP
from sentence_transformers import SentenceTransformer

# ── watch-mode globals ───────────────────────────────────────────────────────
_kb: dict | None = None
_kb_lock = threading.RLock()
_watch_dir: Path | None = None
_watch_interval: float = 2.0

mcp = FastMCP("cic-graph")

# Adjust paths to point to the correct location relative to this script
BASE_DIR = Path(__file__).parent.parent
DATA_DIR = Path(os.environ.get("KB_DATA_DIR", str(Path.cwd() / "kb_data" / "pkl")))

CHUNKS_PKL = Path(os.environ.get("CHUNKS_PKL", str(DATA_DIR / "chunks.pkl")))
NODES_PKL = Path(os.environ.get("NODES_PKL", str(DATA_DIR / "graph_nodes.pkl")))
EDGES_PKL = Path(os.environ.get("EDGES_PKL", str(DATA_DIR / "graph_edges.pkl")))
INVERTED_PKL = Path(os.environ.get("INVERTED_PKL", str(DATA_DIR / "inverted_index.pkl")))
FAISS_INDEX = Path(os.environ.get("FAISS_INDEX", str(DATA_DIR / "faiss.index")))
BM25_PKL = Path(os.environ.get("BM25_PKL", str(DATA_DIR / "bm25.pkl")))
CHUNK_IDS_PKL = Path(os.environ.get("CHUNK_IDS_PKL", str(DATA_DIR / "chunk_ids.pkl")))
MODEL_NAME_PKL = Path(os.environ.get("MODEL_NAME_PKL", str(DATA_DIR / "model_name.pkl")))
METADATA_INDEX_PKL = Path(os.environ.get("METADATA_INDEX_PKL", str(DATA_DIR / "metadata_index.pkl")))

# Limits and Configuration
DEFAULT_TOPK = int(os.environ.get("TOPK", "10"))
MAX_TOPK = int(os.environ.get("MAX_TOPK", "50"))
MAX_NEIGHBORS = int(os.environ.get("MAX_NEIGHBORS", "200"))
MAX_RESOLVE_MATCHES = int(os.environ.get("MAX_RESOLVE_MATCHES", "200"))
MAX_SEARCH_CODE_HITS = int(os.environ.get("MAX_SEARCH_CODE_HITS", "10"))
ENABLE_SEARCH_CODE = os.environ.get("ENABLE_SEARCH_CODE", "true").lower() == "true"

# Rule prioritization constants
RULE_HINTS = [
    "contract",
    "definition of done",
    "dod",
    "limits",
    "symbols",
    "llm lock",
    "llm_lock",
    "golden",
    "verify",
    "commit / pr",
]

RULE_FILE_HINTS = [
    "contract.md",
    "limits.md",
    "symbols.md",
    "llm_lock.md",
    "contributing.md",
    "testing.md",
]


def _clamp_topk(k: int) -> int:
    return max(1, min(int(k), MAX_TOPK))


def _normalize_line_range(val: Any) -> Optional[list[int]]:
    """Normalize line range to [start, end] list of ints or None."""
    if not val:
        return None
    if isinstance(val, list) and len(val) == 2:
        try:
            return [int(val[0]), int(val[1])]
        except (ValueError, TypeError):
            pass
    return None


def load_kb() -> dict[str, Any]:
    """Return the in-memory KB, loading from disk on first call."""
    global _kb
    with _kb_lock:
        if _kb is None:
            _kb = _load_kb_from_disk()
        return _kb


def _load_kb_from_disk() -> dict[str, Any]:
    """Load all PKL artifacts from disk into a fresh dict."""
    def load_one(p: Path) -> Any:
        if not p.exists():
            raise FileNotFoundError(f"Missing: {p}")
        with p.open("rb") as f:
            return pickle.load(f)

    def load_opt(p: Path, default: Any = None) -> Any:
        if not p.exists():
            return default
        with p.open("rb") as f:
            return pickle.load(f)

    chunks = load_one(CHUNKS_PKL)
    nodes = load_opt(NODES_PKL, {})
    edges = load_opt(EDGES_PKL, {})
    inverted = load_opt(INVERTED_PKL, {})

    # Normalize chunks container:
    # Supported:
    # - legacy: chunks.pkl == {"chunks": {cid: {...}, ...}}
    # - alt:    {"chunks": [...]} or {cid: {...}} or [...]
    chunks_by_id: dict[str, dict] = {}
    if isinstance(chunks, dict):
        # legacy wrapper: {"chunks": {id: obj}}
        if "chunks" in chunks and isinstance(chunks["chunks"], dict):
            for k, v in chunks["chunks"].items():
                if isinstance(v, dict):
                    chunks_by_id[str(k)] = v
        # list wrapper: {"chunks": [...]}
        elif "chunks" in chunks and isinstance(chunks["chunks"], list):
            for c in chunks["chunks"]:
                if isinstance(c, dict) and "id" in c:
                    chunks_by_id[str(c["id"])] = c
        else:
            for k, v in chunks.items():
                if isinstance(v, dict):
                    chunks_by_id[str(k)] = v
    elif isinstance(chunks, list):
        for c in chunks:
            if isinstance(c, dict) and "id" in c:
                chunks_by_id[str(c["id"])] = c

    # Nodes container
    # Supported:
    # - legacy: graph_nodes.pkl == {"graph_nodes": {nid: {...}, ...}}
    # - alt:    {"nodes": [...]} or {nid: {...}} or [...]
    nodes_by_id: dict[str, dict] = {}
    if isinstance(nodes, dict):
        # legacy wrapper: {"graph_nodes": {id: obj}}
        if "graph_nodes" in nodes and isinstance(nodes["graph_nodes"], dict):
            for k, v in nodes["graph_nodes"].items():
                if isinstance(v, dict):
                    nodes_by_id[str(k)] = v
        # list wrapper: {"nodes": [...]}
        elif "nodes" in nodes and isinstance(nodes["nodes"], list):
            for n in nodes["nodes"]:
                if isinstance(n, dict) and "id" in n:
                    nodes_by_id[str(n["id"])] = n
        else:
            for k, v in nodes.items():
                if isinstance(v, dict):
                    nodes_by_id[str(k)] = v
    elif isinstance(nodes, list):
        for n in nodes:
            if isinstance(n, dict) and "id" in n:
                nodes_by_id[str(n["id"])] = n

    # Edges container
    edges_list: list[dict] = []
    # Supported:
    # - legacy: graph_edges.pkl == {"graph_edges": {eid: {...}, ...}}
    # - alt:    {"edges": [...]} or {eid: {...}} or [...]
    if isinstance(edges, dict) and "graph_edges" in edges and isinstance(edges["graph_edges"], dict):
        edges_list = [e for e in edges["graph_edges"].values() if isinstance(e, dict)]
    elif isinstance(edges, dict) and "edges" in edges and isinstance(edges["edges"], list):
        edges_list = edges["edges"]
    elif isinstance(edges, dict):
        # dict[eid -> edge_obj]
        edges_list = [e for e in edges.values() if isinstance(e, dict)]
    elif isinstance(edges, list):
        edges_list = edges

    # Build adjacency
    adj: dict[str, list[dict]] = {}
    for e in edges_list:
        if not isinstance(e, dict):
            continue
        src = str(e.get("source") or e.get("from") or e.get("src") or "")
        if not src:
            continue
        adj.setdefault(src, []).append(e)

    # Build chunk_id -> list[node_id] index for fast lookup
    chunk_to_nodes: dict[str, list[str]] = {}
    for nid, node in nodes_by_id.items():
        cid = node.get("chunk_id")
        if cid:
            chunk_to_nodes.setdefault(str(cid), []).append(nid)

    # Inverted index is usually dict[token -> list[{chunk_id, score}]]
    inverted_index: dict[str, list[dict]] = {}
    if isinstance(inverted, dict):
        # legacy: inverted_index.pkl == {"inverted_index": {token: [...]}}
        inverted_index = inverted.get("inverted_index", inverted)

    # Load FAISS index
    faiss_idx = None
    faiss_chunk_ids: list[str] = []
    if FAISS_INDEX.exists() and CHUNK_IDS_PKL.exists():
        faiss_idx = faiss.read_index(str(FAISS_INDEX))
        with CHUNK_IDS_PKL.open("rb") as f:
            faiss_chunk_ids = pickle.load(f)

    # Load BM25 index
    bm25 = None
    if BM25_PKL.exists():
        with BM25_PKL.open("rb") as f:
            bm25 = pickle.load(f)

    # Load embedding model (used for query encoding)
    model_name = "paraphrase-multilingual-MiniLM-L12-v2"
    if MODEL_NAME_PKL.exists():
        with MODEL_NAME_PKL.open("rb") as f:
            model_name = pickle.load(f)
    if faiss_idx is not None:
        try:
            embedding_model = SentenceTransformer(model_name, local_files_only=True)
        except Exception:
            embedding_model = SentenceTransformer(model_name)
    else:
        embedding_model = None

    # Build embeddings_by_id from FAISS vectors — needed for incremental watch updates
    embeddings_by_id: dict[str, np.ndarray] = {}
    if faiss_idx is not None:
        for i, cid in enumerate(faiss_chunk_ids):
            try:
                embeddings_by_id[str(cid)] = faiss_idx.reconstruct(i)
            except Exception:
                pass

    return {
        "chunks": chunks_by_id,
        "nodes": nodes_by_id,
        "edges": edges_list,
        "adj": adj,
        "chunk_to_nodes": chunk_to_nodes,
        "inverted": inverted_index,
        "faiss_index": faiss_idx,
        "faiss_chunk_ids": faiss_chunk_ids,
        "embeddings_by_id": embeddings_by_id,
        "bm25": bm25,
        "embedding_model": embedding_model,
        "meta_idx": load_one(METADATA_INDEX_PKL) if METADATA_INDEX_PKL.exists() else {},
    }


def _tokenize(q: str) -> list[str]:
    # Align closer to make_source.py: lowercase + alpha-only tokens.
    # This also keeps Hungarian accented letters (isalpha() == True).
    # (No stopword removal here to keep server lightweight and deterministic.)
    return [
        w for w in re.findall(r"\w+", q.lower(), flags=re.UNICODE)
        if w.isalpha()
    ]


def _extract_chunk_text(chunk: dict) -> str:
    content = chunk.get("content")
    if isinstance(content, str) and content:
        return content
    text = chunk.get("text")
    if isinstance(text, str):
        return text
    return ""


def _extract_chunk_file_paths(chunk: dict) -> list[str]:
    """Return all file paths for a chunk (dedup-aware: file_paths list)."""
    fps = chunk.get("file_paths")
    if isinstance(fps, list) and fps:
        return [str(p) for p in fps if p]
    meta = chunk.get("metadata", {})
    if not isinstance(meta, dict):
        meta = {}
    single = (
        chunk.get("file_path")
        or meta.get("file_path")
        or chunk.get("path")
        or meta.get("path")
        or ""
    )
    return [str(single)] if single else []


def _extract_chunk_file_path(chunk: dict) -> str:
    """Return the canonical (primary) file path for a chunk."""
    paths = _extract_chunk_file_paths(chunk)
    return paths[0] if paths else ""


def _extract_chunk_section(chunk: dict) -> str:
    meta = chunk.get("metadata", {})
    if not isinstance(meta, dict):
        meta = {}
    return str(
        chunk.get("section")
        or meta.get("section")
        or ""
    )


def _rule_bonus_for_chunk(chunk: dict) -> float:
    """
    Give a deterministic bonus to rule-like chunks/files.
    """
    file_path = _extract_chunk_file_path(chunk).lower()
    section = _extract_chunk_section(chunk).lower()
    text = _extract_chunk_text(chunk)[:1200].lower()

    bonus = 0.0

    for hint in RULE_FILE_HINTS:
        if hint in file_path:
            bonus += 2.0

    for hint in RULE_HINTS:
        if hint in section:
            bonus += 1.5
        if hint in text:
            bonus += 0.75

    return bonus


def _kb_mtimes() -> dict[str, float | None]:
    return {
        "chunks": CHUNKS_PKL.stat().st_mtime if CHUNKS_PKL.exists() else None,
        "nodes": NODES_PKL.stat().st_mtime if NODES_PKL.exists() else None,
        "edges": EDGES_PKL.stat().st_mtime if EDGES_PKL.exists() else None,
        "inverted": INVERTED_PKL.stat().st_mtime if INVERTED_PKL.exists() else None,
    }


@mcp.tool()
def kb_status() -> dict:
    """Return detailed status about loaded KB artifacts."""
    kb = load_kb()
    return {
        "data_dir": str(DATA_DIR),
        "kb_loaded": _kb is not None,
        "watch_dir": str(_watch_dir) if _watch_dir else None,
        "chunks": len(kb.get("chunks", {})),
        "nodes": len(kb.get("nodes", {})),
        "files": {
            "chunks": {
                "path": str(CHUNKS_PKL),
                "exists": CHUNKS_PKL.exists(),
                "mtime": CHUNKS_PKL.stat().st_mtime if CHUNKS_PKL.exists() else None,
                "size": CHUNKS_PKL.stat().st_size if CHUNKS_PKL.exists() else None,
            },
            "nodes": {
                "path": str(NODES_PKL),
                "exists": NODES_PKL.exists(),
                "mtime": NODES_PKL.stat().st_mtime if NODES_PKL.exists() else None,
                "size": NODES_PKL.stat().st_size if NODES_PKL.exists() else None,
            },
            "edges": {
                "path": str(EDGES_PKL),
                "exists": EDGES_PKL.exists(),
                "mtime": EDGES_PKL.stat().st_mtime if EDGES_PKL.exists() else None,
                "size": EDGES_PKL.stat().st_size if EDGES_PKL.exists() else None,
            },
            "inverted": {
                "path": str(INVERTED_PKL),
                "exists": INVERTED_PKL.exists(),
                "mtime": INVERTED_PKL.stat().st_mtime if INVERTED_PKL.exists() else None,
                "size": INVERTED_PKL.stat().st_size if INVERTED_PKL.exists() else None,
            },
            "faiss": {
                "path": str(FAISS_INDEX),
                "exists": FAISS_INDEX.exists(),
                "mtime": FAISS_INDEX.stat().st_mtime if FAISS_INDEX.exists() else None,
                "size": FAISS_INDEX.stat().st_size if FAISS_INDEX.exists() else None,
            },
            "bm25": {
                "path": str(BM25_PKL),
                "exists": BM25_PKL.exists(),
                "mtime": BM25_PKL.stat().st_mtime if BM25_PKL.exists() else None,
                "size": BM25_PKL.stat().st_size if BM25_PKL.exists() else None,
            },
        }
    }


@mcp.tool()
def reload_kb() -> dict:
    """
    Force reload of KB artifacts from disk.
    Useful after regenerating PKL files outside of watch mode.
    """
    global _kb
    before = _kb_mtimes()
    with _kb_lock:
        _kb = _load_kb_from_disk()
        kb = _kb
    after = _kb_mtimes()

    return {
        "reloaded": True,
        "chunks": len(kb["chunks"]),
        "nodes": len(kb["nodes"]),
        "edges": len(kb["edges"]),
        "tokens": len(kb["inverted"]),
        "mtimes_before": before,
        "mtimes_after": after,
    }


# ── in-process watch (--watch-dir) ──────────────────────────────────────────

def _watch_process_file(file_path: str) -> list:
    """Route a changed file to the correct make_source processor."""
    import sys as _sys
    _sys.path.insert(0, str(Path(__file__).parent.parent))
    import make_source as _ms  # noqa: PLC0415

    if file_path.endswith('.md'):
        return _ms.process_md_file(file_path)
    if file_path.endswith(('.yaml', '.yml')):
        base = os.path.splitext(file_path)[0]
        if os.path.exists(base + '.go') or _ms._is_go_meta_yaml(file_path):
            return _ms.process_go_yaml(file_path)
        if os.path.exists(base + '.py') or _ms._is_py_meta_yaml(file_path):
            return _ms.process_py_yaml(file_path)
        if os.path.exists(base + '.md'):
            return []
        return _ms.process_yaml_file(file_path)
    return []


def _incremental_update_kb(changed: list, deleted: list) -> dict:
    """Apply file changes to the in-memory KB. Must be called under _kb_lock."""
    import sys as _sys
    _sys.path.insert(0, str(Path(__file__).parent.parent))
    import make_source as _ms  # noqa: PLC0415

    kb = _kb
    if kb is None:
        return {'removed': 0, 'added': 0, 'total': 0}

    # Remove stale chunks (changed files will be re-added below)
    fp_set = set(changed + deleted)
    stale_ids = {
        cid for cid, c in kb['chunks'].items()
        if fp_set & set(c.get('file_paths', [c.get('file_path', '')]))
    }
    for cid in stale_ids:
        kb['chunks'].pop(cid, None)
        kb['embeddings_by_id'].pop(cid, None)

    # Reprocess changed files
    new_chunks: list = []
    for fp in changed:
        try:
            new_chunks.extend(_watch_process_file(fp))
        except Exception as exc:
            print(f"[watch] warn {os.path.basename(fp)}: {exc}", flush=True)

    # Assign IDs continuing from current max
    nums = [int(c[1:]) for c in kb['chunks'] if c.startswith('c') and c[1:].isdigit()]
    next_id = max(nums, default=0) + 1
    for i, chunk in enumerate(new_chunks):
        chunk['id'] = f'c{next_id + i}'
        chunk.setdefault('file_paths', [chunk.get('file_path', '')])

    # Embed only new chunks — model already loaded
    model = kb.get('embedding_model')
    if new_chunks and model:
        texts = [c.get('text', '') for c in new_chunks]
        vecs = model.encode(texts, normalize_embeddings=True, batch_size=32, show_progress_bar=False)
        for chunk, vec in zip(new_chunks, vecs):
            kb['chunks'][chunk['id']] = chunk
            kb['embeddings_by_id'][chunk['id']] = vec.astype('float32')

    # Rebuild FAISS from all current embeddings (no re-encoding)
    emb = kb['embeddings_by_id']
    if emb:
        id_order = list(emb.keys())
        mat = np.stack([emb[cid] for cid in id_order]).astype('float32')
        new_idx = faiss.IndexFlatIP(mat.shape[1])
        new_idx.add(mat)
        kb['faiss_index'] = new_idx
        kb['faiss_chunk_ids'] = id_order

    # Rebuild BM25 + inverted index from all current chunks (fast — no encoding)
    all_chunks = list(kb['chunks'].values())
    if all_chunks:
        bm25 = _ms.build_bm25_index(all_chunks)
        kb['inverted'] = _ms.create_bm25_inverted_index(all_chunks, bm25)
        kb['bm25'] = bm25

    # Rebuild knowledge graph from all current chunks + embeddings (no re-encoding)
    emb = kb['embeddings_by_id']
    if all_chunks and emb:
        id_order = [c['id'] for c in all_chunks if c['id'] in emb]
        emb_mat = np.stack([emb[cid] for cid in id_order]).astype('float32')
        ordered_chunks = [kb['chunks'][cid] for cid in id_order]
        nodes_list, edges_list = _ms.create_knowledge_graph_with_content(ordered_chunks, emb_mat)
        kb['nodes'] = {n['id']: n for n in nodes_list}
        kb['edges'] = edges_list
        adj: dict = {}
        for e in edges_list:
            src = str(e.get('source') or e.get('from') or e.get('src') or '')
            if src:
                adj.setdefault(src, []).append(e)
        kb['adj'] = adj
        chunk_to_nodes: dict = {}
        for nid, node in kb['nodes'].items():
            cid = node.get('chunk_id')
            if cid:
                chunk_to_nodes.setdefault(str(cid), []).append(nid)
        kb['chunk_to_nodes'] = chunk_to_nodes

    return {'removed': len(stale_ids), 'added': len(new_chunks), 'total': len(kb['chunks']),
            'nodes': len(kb.get('nodes', {})), 'edges': len(kb.get('edges', []))}


def _file_hash(path: str) -> str:
    try:
        with open(path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return ''


def _scan_watch_dir(watch_dir: Path) -> dict:
    result = {}
    for root, _, files in os.walk(watch_dir):
        for fname in files:
            if any(fname.endswith(e) for e in ('.md', '.yaml', '.yml')) and not fname.startswith('.'):
                p = os.path.join(root, fname)
                result[p] = _file_hash(p)
    return result


def _bootstrap_kb_from_source(source_dir: Path) -> None:
    """Build PKL artifacts from source_dir when starting fresh (no chunks.pkl)."""
    import sys as _sys
    _sys.path.insert(0, str(Path(__file__).parent.parent))
    import make_source as _ms  # noqa: PLC0415

    print(f"[boot] scanning {source_dir} ...", flush=True)
    chunks = _ms.process_directory(str(source_dir))
    chunks = _ms._dedup_chunks(chunks)
    chunks.sort(key=lambda c: (c.get('file_path', ''), c.get('start_line', 0)))
    for i, chunk in enumerate(chunks):
        chunk['id'] = f'c{i + 1}'

    print(f"[boot] {len(chunks)} chunks — embedding ...", flush=True)
    model_name = _ms.EMBEDDING_MODEL
    model, embeddings = _ms.create_embeddings([c['text'] for c in chunks], model_name)

    print("[boot] building indexes ...", flush=True)
    bm25 = _ms.build_bm25_index(chunks)
    inv = _ms.create_bm25_inverted_index(chunks, bm25)
    faiss_idx = _ms.build_faiss_index(embeddings)

    print("[boot] building knowledge graph ...", flush=True)
    nodes_list, edges_list = _ms.create_knowledge_graph_with_content(chunks, embeddings)

    pkl_dir = DATA_DIR
    pkl_dir.mkdir(parents=True, exist_ok=True)

    import pickle as _pickle
    for name, obj in [
        ('chunks.pkl', {c['id']: c for c in chunks}),
        ('inverted_index.pkl', inv),
        ('bm25.pkl', bm25),
        ('chunk_ids.pkl', [c['id'] for c in chunks]),
        ('model_name.pkl', model_name),
        ('graph_nodes.pkl', {n['id']: n for n in nodes_list}),
        ('graph_edges.pkl', {e['id']: e for e in edges_list if 'id' in e}),
    ]:
        (pkl_dir / name).write_bytes(_pickle.dumps(obj))

    faiss.write_index(faiss_idx, str(pkl_dir / 'faiss.index'))

    # Persist file state for the watcher
    current = _scan_watch_dir(source_dir)
    (DATA_DIR.parent / '.file_state.json').write_text(json.dumps(current, indent=2))

    print(f"[boot] done — {len(chunks)} chunks, {len(nodes_list)} nodes, {len(edges_list)} edges → {pkl_dir}", flush=True)


def _watch_loop() -> None:
    """Background daemon thread: polls watch_dir, applies incremental updates."""
    state_path = DATA_DIR.parent / '.file_state.json'
    try:
        file_state: dict = json.loads(state_path.read_text()) if state_path.exists() else {}
    except Exception:
        file_state = {}

    print(f"[watch] watching {_watch_dir}  interval={_watch_interval}s", flush=True)
    while True:
        time.sleep(_watch_interval)
        try:
            current = _scan_watch_dir(_watch_dir)
            changed = [p for p, h in current.items() if file_state.get(p) != h]
            deleted = [p for p in file_state if p not in current]
            if changed or deleted:
                ts = time.strftime('%H:%M:%S')
                print(f"[watch {ts}] {len(changed)} changed, {len(deleted)} deleted", flush=True)
                with _kb_lock:
                    s = _incremental_update_kb(changed, deleted)
                file_state = current
                state_path.write_text(json.dumps(file_state, indent=2))
                print(f"[watch] removed={s['removed']} added={s['added']} total={s['total']}", flush=True)
        except Exception as exc:
            print(f"[watch] error: {exc}", flush=True)


# ── MCP tools ────────────────────────────────────────────────────────────────

@mcp.tool()
def list_edge_types() -> list[str]:
    """List all unique edge types found in the graph."""
    kb = load_kb()
    types = set()
    for e in kb["edges"]:
        if isinstance(e, dict):
            t = e.get("type") or e.get("edge_type")
            if t:
                types.add(str(t))
    return sorted(types)


@mcp.tool()
def list_node_types() -> list[str]:
    """List all unique node types (categories) found in the graph."""
    kb = load_kb()
    types = set()
    for n in kb["nodes"].values():
        if isinstance(n, dict):
            # Try 'type' or 'category'
            t = n.get("type") or n.get("category")
            if t:
                if isinstance(t, list):
                    for x in t:
                        types.add(str(x))
                else:
                    types.add(str(t))
    return sorted(types)


@mcp.tool()
def search_token(token: str, top_k: int = DEFAULT_TOPK) -> list[dict]:
    """Lexical single-token search using BM25.

    Returns a list of {chunk_id, score}.
    """
    kb = load_kb()
    bm25 = kb.get("bm25")
    chunk_ids = kb.get("faiss_chunk_ids", [])

    if bm25 is None or not chunk_ids:
        # fallback: inverted index
        t = token.strip().lower()
        hits = kb["inverted"].get(t, [])
        hits_sorted = sorted(
            (h for h in hits if isinstance(h, dict) and "chunk_id" in h),
            key=lambda x: float(x.get("score", 0.0)),
            reverse=True,
        )
        return hits_sorted[:_clamp_topk(top_k)]

    scores = bm25.get_scores([token.strip().lower()])
    indexed = [(chunk_ids[i], float(s)) for i, s in enumerate(scores) if s > 0.01]
    indexed.sort(key=lambda x: x[1], reverse=True)
    return [{"chunk_id": cid, "score": sc} for cid, sc in indexed[:_clamp_topk(top_k)]]


@mcp.tool()
def search_query(query: str, top_k: int = DEFAULT_TOPK, threshold: float = 0.0) -> list[dict]:
    """Semantic search using FAISS + multilingual embeddings.

    Returns ranked chunks: {chunk_id, score, file_path, line_range}.
    Falls back to BM25 inverted index if FAISS is not available.
    """
    kb = load_kb()
    faiss_idx = kb.get("faiss_index")
    model = kb.get("embedding_model")
    chunk_ids = kb.get("faiss_chunk_ids", [])

    if faiss_idx is None or model is None or not chunk_ids:
        # fallback: BM25 / inverted index
        tokens = _tokenize(query)
        if not tokens:
            return []
        scores: dict[str, float] = {}
        matched: dict[str, set[str]] = {}
        for t in tokens:
            for h in kb["inverted"].get(t, []):
                if not isinstance(h, dict):
                    continue
                cid = str(h.get("chunk_id", ""))
                if not cid:
                    continue
                s = float(h.get("score", 0.0))
                scores[cid] = scores.get(cid, 0.0) + s
                matched.setdefault(cid, set()).add(t)
        ranked = sorted([(c, s) for c, s in scores.items() if s >= threshold], key=lambda x: x[1], reverse=True)
        results = []
        for cid, sc in ranked[:_clamp_topk(top_k)]:
            chunk = kb["chunks"].get(cid, {})
            meta = chunk.get("metadata", {}) or {}
            results.append({
                "chunk_id": cid,
                "score": sc,
                "matched_tokens": sorted(matched.get(cid, set())),
                "file_paths": _extract_chunk_file_paths(chunk),
                "line_range": _normalize_line_range(chunk.get("line_range") or meta.get("line_range")),
            })
        return results

    query_vec = model.encode([query], normalize_embeddings=True).astype("float32")
    k = _clamp_topk(top_k)
    scores_arr, indices = faiss_idx.search(query_vec, k)

    results = []
    for score, idx in zip(scores_arr[0], indices[0]):
        if idx < 0 or float(score) < threshold:
            continue
        cid = chunk_ids[idx]
        chunk = kb["chunks"].get(cid, {})
        meta = chunk.get("metadata", {}) or {}
        results.append({
            "chunk_id": cid,
            "score": float(score),
            "matched_tokens": [],
            "file_paths": _extract_chunk_file_paths(chunk),
            "line_range": _normalize_line_range(chunk.get("line_range") or meta.get("line_range")),
        })
    return results


@mcp.tool()
def search_code(code_snippet: str, top_k: int = DEFAULT_TOPK) -> list[dict]:
    """Substring search in chunk content (slow, linear scan).

    Useful for finding exact code snippets or literal strings that token search misses.
    Returns: {chunk_id, content_preview, file_path, line_range}
    """
    if not ENABLE_SEARCH_CODE:
        return []

    kb = load_kb()
    snippet = code_snippet.strip()
    if not snippet:
        return []

    results = []
    # Use stricter limit for linear scan
    limit = min(_clamp_topk(top_k), MAX_SEARCH_CODE_HITS)

    for cid, chunk in kb["chunks"].items():
        if not isinstance(chunk, dict):
            continue
        content = chunk.get("content") or chunk.get("text") or ""
        if not isinstance(content, str):
            continue

        if snippet in content:
            # Simple preview: 50 chars around the match
            idx = content.find(snippet)
            start = max(0, idx - 50)
            end = min(len(content), idx + len(snippet) + 50)
            preview = "..." + content[start:end].replace("\n", " ") + "..."

            # Extract metadata
            meta = chunk.get("metadata", {})
            if not isinstance(meta, dict):
                meta = {}

            file_path = (
                chunk.get("file_path") or
                meta.get("file_path") or
                chunk.get("path") or
                meta.get("path")
            )

            raw_lines = (
                chunk.get("line_range") or
                meta.get("line_range") or
                chunk.get("lines") or
                meta.get("lines")
            )
            line_range = _normalize_line_range(raw_lines)

            results.append({
                "chunk_id": cid,
                "preview": preview,
                "file_paths": _extract_chunk_file_paths(chunk),
                "line_range": line_range
            })
            if len(results) >= limit:
                break

    return results


@mcp.tool()
def search_nodes(query: str, top_k: int = DEFAULT_TOPK) -> list[dict]:
    """Search for nodes by name, label, type, tags, or category.

    Uses the metadata index for O(1) tag/category lookup, then augments
    with linear label/type scan for full coverage.
    """
    kb = load_kb()
    q = query.lower().strip()
    limit = _clamp_topk(top_k)
    meta_idx = kb.get("meta_idx", {})

    # Collect candidate chunk_ids from metadata index (O(1))
    boosted_chunks: dict[str, int] = {}
    for tag, cids in meta_idx.get("tag_index", {}).items():
        if q in tag.lower():
            for cid in cids:
                boosted_chunks[cid] = boosted_chunks.get(cid, 0) + 2
    for cat, cids in meta_idx.get("category_index", {}).items():
        if q in cat.lower():
            for cid in cids:
                boosted_chunks[cid] = boosted_chunks.get(cid, 0) + 2

    # Map chunk_ids back to node_ids for boosted set
    chunk_to_nodes = kb.get("chunk_to_nodes", {})
    boosted_nodes: dict[str, int] = {}
    for cid, bonus in boosted_chunks.items():
        for nid in chunk_to_nodes.get(cid, []):
            boosted_nodes[nid] = boosted_nodes.get(nid, 0) + bonus

    # Linear scan for label/type/id matches
    scores: dict[str, int] = dict(boosted_nodes)
    for nid, node in kb["nodes"].items():
        if not isinstance(node, dict):
            continue
        s = scores.get(nid, 0)
        if q in str(nid).lower():
            s += 4
        label = str(node.get("label") or node.get("name") or "")
        if q in label.lower():
            s += 3
        cat = str(node.get("type") or "")
        if q in cat.lower():
            s += 1
        if s > 0:
            scores[nid] = s

    results = []
    for nid, score in scores.items():
        node = kb["nodes"].get(nid)
        if not isinstance(node, dict):
            continue
        label = str(node.get("label") or node.get("name") or "")
        results.append({
            "node_id": nid,
            "score": score,
            "label": label,
            "type": str(node.get("type") or ""),
            "tags": node.get("tags", []),
            "category": node.get("category", []),
            "chunk_id": node.get("chunk_id"),
        })

    # Sort by score
    results.sort(key=lambda x: x["score"], reverse=True)
    return results[:limit]


@mcp.tool()
def resolve_path(file_path: str, mode: str = "prefix", limit: int = 200) -> list[dict]:
    """Find chunks belonging to a specific file path.

    Args:
        file_path: The path string to search for.
        mode: Matching mode.
            - "prefix": Matches if chunk path starts with file_path (default).
            - "contains": Matches if file_path is a substring of chunk path.
            - "exact": Matches if chunk path equals file_path.
        limit: Max number of chunks to return (default 200).

    Returns: list of {chunk_id, line_range, file_path}
    """
    kb = load_kb()
    target = file_path.strip().lower()
    results = []
    mode = mode.lower()

    # Clamp limit
    max_res = max(1, min(limit, MAX_RESOLVE_MATCHES))

    for cid, chunk in kb["chunks"].items():
        if not isinstance(chunk, dict):
            continue

        meta = chunk.get("metadata", {})
        if not isinstance(meta, dict):
            meta = {}

        # Check against all paths (dedup-aware)
        all_paths = _extract_chunk_file_paths(chunk)
        matched_paths = []
        for path_raw in all_paths:
            path_str = path_raw.lower()
            if mode == "exact":
                hit = (path_str == target)
            elif mode == "contains":
                hit = (target in path_str)
            else:  # prefix (default)
                hit = path_str.startswith(target)
            if hit:
                matched_paths.append(path_raw)

        if matched_paths:
            raw_lines = (
                chunk.get("line_range") or
                meta.get("line_range") or
                chunk.get("lines") or
                meta.get("lines")
            )
            line_range = _normalize_line_range(raw_lines)

            results.append({
                "chunk_id": cid,
                "file_paths": all_paths,
                "matched_paths": matched_paths,
                "line_range": line_range,
            })

            if len(results) >= max_res:
                break

    return results


@mcp.tool()
def get_chunk(chunk_id: str, max_chars: int = 8000) -> Optional[dict]:
    """Return a chunk by id.

    Args:
        chunk_id: The ID of the chunk.
        max_chars: Maximum characters of content to return (default 8000).
    """
    kb = load_kb()
    chunk = kb["chunks"].get(str(chunk_id))
    if not chunk:
        return None

    # Create a copy to avoid modifying the cached object
    out = chunk.copy()

    # Truncate content if present
    content = out.get("content") or out.get("text")
    if isinstance(content, str) and len(content) > max_chars:
        out["content"] = content[:max_chars] + "... (truncated)"
        # Also update 'text' alias if present
        if "text" in out:
            out["text"] = out["content"]

    return out


@mcp.tool()
def get_node(node_id: str) -> Optional[dict]:
    """Return a node by id."""
    kb = load_kb()
    return kb["nodes"].get(str(node_id))


@mcp.tool()
def neighbors(node_id: str, edge_type: Optional[str] = None, limit: int = 50) -> list[dict]:
    """Return outgoing edges from a node. Optionally filter by edge_type."""
    kb = load_kb()
    outs = kb["adj"].get(str(node_id), [])
    if edge_type:
        outs = [e for e in outs if str(e.get("type") or e.get("edge_type") or "").lower() == edge_type.lower()]

    # Use MAX_NEIGHBORS instead of MAX_TOPK
    max_n = max(1, min(limit, MAX_NEIGHBORS))
    return outs[:max_n]

@mcp.tool()
def focus_pack(query: str, depth: int = 1, top_k: int = 5, max_rules: int = 3) -> dict:
    """
    Build an enriched task context bundle.

    Compared to standard search:
    - prioritizes rule-like chunks/files (CONTRACT, DoD, LIMITS)
    - returns 'key_rules'
    - returns 'recommended_reading_order'
    """
    kb = load_kb()

    # Safety limits
    depth = max(0, min(int(depth), 2))
    limit = max(1, min(int(top_k), MAX_TOPK))
    max_rules = max(1, min(int(max_rules), 10))

    # 1) Base search
    hits = search_query(query, top_k=limit)
    if not hits:
        return {
            "query": query,
            "primary_nodes": [],
            "related_nodes": [],
            "chunks": [],
            "files": [],
            "key_rules": [],
            "recommended_reading_order": [],
        }

    chunk_ids = [str(h["chunk_id"]) for h in hits if "chunk_id" in h]
    base_score_map = {str(h["chunk_id"]): float(h.get("score", 0.0)) for h in hits if "chunk_id" in h}

    # 2) Chunk -> Node mapping (using pre-built index)
    primary_nodes_set = set()
    for cid in chunk_ids:
        nodes = kb["chunk_to_nodes"].get(cid, [])
        primary_nodes_set.update(nodes)
    primary_nodes = list(primary_nodes_set)

    # 3) Graph expansion
    related_nodes = set(primary_nodes)
    frontier = list(primary_nodes)

    for _ in range(depth):
        new_frontier = []
        for node_id in frontier:
            for e in kb["adj"].get(node_id, []):
                # Robust edge target extraction
                target = str(e.get("target") or e.get("to") or e.get("dest") or e.get("dst") or "")
                if target and target not in related_nodes:
                    related_nodes.add(target)
                    new_frontier.append(target)
        frontier = new_frontier

    # 4) Node -> Chunk expansion
    related_chunks = set(chunk_ids)
    for node_id in related_nodes:
        node = kb["nodes"].get(node_id)
        if node and node.get("chunk_id"):
            related_chunks.add(str(node["chunk_id"]))

    # 5) Collect chunk details and score with rule bonuses
    scored_chunks_data: list[dict] = [] # Store {cid, final_score, rule_bonus, chunk_obj}
    files = set()

    for cid in related_chunks:
        chunk = kb["chunks"].get(cid)
        if not isinstance(chunk, dict):
            continue

        file_path = _extract_chunk_file_path(chunk)
        if file_path:
            files.add(file_path)

        rule_bonus = _rule_bonus_for_chunk(chunk)
        final_score = base_score_map.get(cid, 0.0) + rule_bonus

        scored_chunks_data.append({
            "cid": cid,
            "final_score": final_score,
            "rule_bonus": rule_bonus,
            "chunk": chunk
        })

    # Sort by final score
    scored_chunks_data.sort(key=lambda x: x["final_score"], reverse=True)

    # Cap results to avoid context flooding (max 50 chunks)
    chunks_sorted = [x["cid"] for x in scored_chunks_data][:50]

    # 6) Pick top rule-like chunks
    key_rules: list[dict] = []
    for item in scored_chunks_data:
        if item["rule_bonus"] <= 0:
            continue

        chunk = item["chunk"]
        key_rules.append({
            "chunk_id": item["cid"],
            "score": item["final_score"],
            "file_path": _extract_chunk_file_path(chunk),
            "section": _extract_chunk_section(chunk),
        })

        if len(key_rules) >= max_rules:
            break

    # 7) Recommended reading order = rule chunks first, then high-score direct hits
    recommended_files: list[str] = []
    seen_files = set()

    for rule in key_rules:
        fp = rule.get("file_path")
        if fp and fp not in seen_files:
            recommended_files.append(fp)
            seen_files.add(fp)

    for cid in chunks_sorted:
        chunk = kb["chunks"].get(cid)
        if not isinstance(chunk, dict):
            continue
        fp = _extract_chunk_file_path(chunk)
        if fp and fp not in seen_files:
            recommended_files.append(fp)
            seen_files.add(fp)

    return {
        "query": query,
        "primary_nodes": primary_nodes,
        "related_nodes": sorted(list(related_nodes)),
        "chunks": chunks_sorted,
        "files": sorted(files),
        "key_rules": key_rules,
        "recommended_reading_order": recommended_files,
    }

@mcp.tool()
def explain_node(node_id: str) -> dict:
    """
    Deep dive into a specific node: returns definition, neighbors,
    associated chunk content, and related files.
    """
    kb = load_kb()
    node = kb["nodes"].get(str(node_id))
    if not node:
        return {"error": f"Node {node_id} not found"}

    # Neighbors (direct access for speed)
    out_edges = kb["adj"].get(str(node_id), [])[:20]

    # Chunk context
    chunk_info = {}
    cid = node.get("chunk_id")
    if cid:
        chunk = kb["chunks"].get(str(cid))
        if chunk:
            chunk_info = {
                "chunk_id": cid,
                "text": _extract_chunk_text(chunk)[:2000], # Preview
                "file_path": _extract_chunk_file_path(chunk),
                "rule_bonus": _rule_bonus_for_chunk(chunk)
            }

    return {
        "node": node,
        "neighbors": out_edges,
        "context": chunk_info
    }

@mcp.tool()
def find_nodes(
    category: Optional[str] = None,
    tag: Optional[str] = None,
    used_in: Optional[str] = None,
    top_k: int = 50,
) -> list[dict]:
    """Filter nodes by metadata using the prebuilt metadata index (O(1) lookup).

    Args:
        category: Filter by category (exact match).
        tag:      Filter by tag (exact match).
        used_in:  Filter by used_in context (exact match).
        top_k:    Max results.
    """
    kb = load_kb()
    meta_idx = kb.get("meta_idx", {})
    chunk_to_nodes = kb.get("chunk_to_nodes", {})
    limit = _clamp_topk(top_k)

    # Start with the full set of chunk_ids, then intersect per filter
    candidate_sets: list[set[str]] = []

    if tag:
        cids = set(meta_idx.get("tag_index", {}).get(tag.lower(), []))
        candidate_sets.append(cids)
    if category:
        cids = set(meta_idx.get("category_index", {}).get(category.lower(), []))
        candidate_sets.append(cids)
    if used_in:
        cids = set(meta_idx.get("used_in_index", {}).get(used_in.lower(), []))
        candidate_sets.append(cids)

    if not candidate_sets:
        return []

    # Intersect all filter sets
    matched_chunks = candidate_sets[0]
    for s in candidate_sets[1:]:
        matched_chunks = matched_chunks & s

    # Resolve chunk_ids → nodes
    out: list[dict] = []
    for cid in matched_chunks:
        for nid in chunk_to_nodes.get(cid, []):
            node = kb["nodes"].get(nid)
            if isinstance(node, dict):
                out.append(node)
            if len(out) >= limit:
                return out
    return out


@mcp.tool()
def impact_analysis(node_id: str, max_depth: int = 3) -> dict:
    """Analyse the downstream impact of a node: what depends on it, critical paths, used_in coverage.

    Performs BFS from node_id through the adjacency graph, collects all reachable downstream
    nodes, aggregates used_in fields, and identifies critical path nodes (highest fan-out).

    Args:
        node_id: The node to start from.
        max_depth: BFS depth limit (default 3, max 5).
    """
    kb = load_kb()
    nodes = kb["nodes"]
    adj = kb["adj"]

    max_depth = max(1, min(int(max_depth), 5))
    start = str(node_id)

    if start not in nodes:
        return {"error": f"node '{node_id}' not found"}

    # BFS
    visited: dict[str, int] = {start: 0}   # node_id -> depth
    queue: list[tuple[str, int]] = [(start, 0)]
    fan_out: dict[str, int] = {}             # node_id -> number of direct children found

    while queue:
        current, depth = queue.pop(0)
        if depth >= max_depth:
            continue
        edges = adj.get(current, [])
        fan_out[current] = len(edges)
        for edge in edges:
            target = str(edge.get("target") or edge.get("to") or edge.get("dest") or edge.get("dst") or "")
            if not target or target in visited:
                continue
            visited[target] = depth + 1
            queue.append((target, depth + 1))

    # Collect used_in from all visited nodes
    used_in_agg: dict[str, list[str]] = {}
    downstream: list[dict] = []
    for nid, depth in visited.items():
        if nid == start:
            continue
        node = nodes.get(nid)
        if not isinstance(node, dict):
            continue
        entry = {
            "node_id": nid,
            "label": node.get("label", nid),
            "type": node.get("type", ""),
            "depth": depth,
            "chunk_id": node.get("chunk_id", ""),
        }
        downstream.append(entry)
        for ui in node.get("used_in") or []:
            used_in_agg.setdefault(str(ui), []).append(nid)

    # Critical path: nodes with highest fan-out (excluding start)
    critical = sorted(
        [{"node_id": nid, "fan_out": fo, "label": nodes.get(nid, {}).get("label", nid)}
         for nid, fo in fan_out.items() if nid != start and fo > 0],
        key=lambda x: x["fan_out"],
        reverse=True,
    )[:10]

    return {
        "node_id": start,
        "label": nodes.get(start, {}).get("label", start),
        "total_downstream": len(downstream),
        "max_depth_reached": max(visited.values()) if visited else 0,
        "downstream": downstream,
        "used_in_coverage": {k: v for k, v in sorted(used_in_agg.items(), key=lambda x: -len(x[1]))},
        "critical_paths": critical,
    }


@mcp.tool()
def guided_path(topic: str, max_steps: int = 10) -> dict:
    """Build an ordered learning path for a topic through the knowledge graph.

    Selects entrypoint nodes matching the topic, then traverses the graph in
    category priority order (concept → architecture → flow → implementation)
    to return a structured reading sequence.

    Args:
        topic: The topic or concept to learn about.
        max_steps: Maximum nodes in the path (default 10, max 20).
    """
    kb = load_kb()
    nodes = kb["nodes"]
    adj = kb["adj"]
    chunk_to_nodes = kb.get("chunk_to_nodes", {})

    max_steps = max(1, min(int(max_steps), 20))

    CATEGORY_PRIORITY = ["concept", "architecture", "flow", "implementation", "spec", "config", "test"]

    def _cat_rank(node: dict) -> int:
        cats = node.get("category") or []
        if isinstance(cats, str):
            cats = [cats]
        for i, c in enumerate(CATEGORY_PRIORITY):
            if any(c in str(cat).lower() for cat in cats):
                return i
        return len(CATEGORY_PRIORITY)

    # 1) Find candidates via search
    hits = search_query(topic, top_k=20)
    candidate_node_ids: list[str] = []
    seen_chunks: set[str] = set()
    for h in hits:
        cid = str(h.get("chunk_id", ""))
        if not cid or cid in seen_chunks:
            continue
        seen_chunks.add(cid)
        for nid in chunk_to_nodes.get(cid, []):
            if nid not in candidate_node_ids:
                candidate_node_ids.append(nid)

    if not candidate_node_ids:
        return {"topic": topic, "path": [], "note": "no nodes found for topic"}

    # 2) Prefer entrypoints as starting nodes
    entrypoints = [nid for nid in candidate_node_ids if nodes.get(nid, {}).get("entrypoint")]
    start_pool = entrypoints if entrypoints else candidate_node_ids[:5]

    # Sort start_pool by category priority
    start_pool = sorted(start_pool, key=lambda nid: _cat_rank(nodes.get(nid, {})))
    start = start_pool[0]

    # 3) BFS guided by category priority
    path: list[dict] = []
    visited: set[str] = set()
    queue: list[tuple[str, str]] = [(start, "entrypoint — best match for topic")]

    while queue and len(path) < max_steps:
        current, reason = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)

        node = nodes.get(current)
        if not isinstance(node, dict):
            continue

        path.append({
            "node_id": current,
            "label": node.get("label", current),
            "type": node.get("type", ""),
            "category": node.get("category", []),
            "chunk_id": node.get("chunk_id", ""),
            "entrypoint": bool(node.get("entrypoint")),
            "reason": reason,
        })

        # Expand neighbours, prioritise by category rank
        edges = adj.get(current, [])
        children: list[tuple[str, str]] = []
        for edge in edges:
            target = str(edge.get("target") or edge.get("to") or edge.get("dest") or edge.get("dst") or "")
            if not target or target in visited:
                continue
            edge_type = str(edge.get("type") or edge.get("edge_type") or "related")
            children.append((target, f"via {edge_type} from {node.get('label', current)}"))

        # Sort children by category priority
        children.sort(key=lambda x: _cat_rank(nodes.get(x[0], {})))
        queue = children + queue   # depth-first within priority

    return {
        "topic": topic,
        "start_node": start,
        "entrypoints_found": len(entrypoints),
        "path": path,
    }


SOURCE_DIR = Path(os.environ.get("SOURCE_DIR", str(Path.cwd())))


_COMPANION_LANGS = {
    "go": {"glob": "*.go", "is_test": lambda name: "_test.go" in name},
    "py": {"glob": "*.py", "is_test": lambda name: name.startswith("test_") or name.endswith("_test.py")},
}


@mcp.tool()
def missing_companions(
    source_dir: str = "",
    langs: Optional[list[str]] = None,
    include_empty_semantic: bool = True,
    limit: int = 50,
) -> dict:
    """List Go/Python source files that lack a companion YAML or have empty semantic fields.

    Scans the source directory for .go and .py files (per `langs`) and reports:
    - 'missing': source files with no companion .yaml at all
    - 'incomplete': companion YAMLs exist but category/used_in/related_nodes are all empty

    Results are sorted by file size descending (larger = higher priority).

    Args:
        source_dir: Override the scan root (default: SOURCE_DIR env or source/).
        langs: Which source languages to scan. Default: ["go", "py"].
        include_empty_semantic: Also report companions with no semantic fields filled.
        limit: Max entries per category (default 50).
    """
    import yaml as _yaml

    scan_root = Path(source_dir) if source_dir else SOURCE_DIR
    if not scan_root.exists():
        return {"error": f"source_dir not found: {scan_root}"}

    selected = langs or list(_COMPANION_LANGS)
    unknown = [lang for lang in selected if lang not in _COMPANION_LANGS]
    if unknown:
        return {"error": f"unknown lang(s): {unknown}. allowed: {list(_COMPANION_LANGS)}"}

    missing: list[dict] = []
    incomplete: list[dict] = []

    for lang in selected:
        spec = _COMPANION_LANGS[lang]
        for src_file in sorted(scan_root.rglob(spec["glob"])):
            if spec["is_test"](src_file.name):
                continue
            companion = src_file.with_suffix(".yaml")
            rel = str(src_file.relative_to(scan_root))
            size = src_file.stat().st_size

            if not companion.exists():
                missing.append({"file": rel, "lang": lang, "size": size})
                continue

            if not include_empty_semantic:
                continue

            try:
                with companion.open() as f:
                    data = _yaml.safe_load(f) or {}
            except Exception:
                continue

            cat = data.get("category") or []
            used = data.get("used_in") or []
            related = data.get("related_nodes") or []
            desc = (data.get("description") or "").strip()

            if not cat and not used and not related and not desc:
                incomplete.append({
                    "file": rel, "lang": lang,
                    "companion": str(companion.relative_to(scan_root)), "size": size,
                })

    missing.sort(key=lambda x: -x["size"])
    incomplete.sort(key=lambda x: -x["size"])

    return {
        "scan_root": str(scan_root),
        "missing_count": len(missing),
        "incomplete_count": len(incomplete),
        "missing": missing[:limit],
        "incomplete": incomplete[:limit],
    }


# PROMPTMAP_PATHS: colon-separated list of absolute paths to PROMPTMAP.yaml files.
# If not set, the tools scan SOURCE_DIR recursively.
_PROMPTMAP_PATHS_ENV = os.environ.get("PROMPTMAP_PATHS", "")


def _find_promptmaps() -> list[Path]:
    """Return all known PROMPTMAP.yaml paths (env override or source dir scan)."""
    if _PROMPTMAP_PATHS_ENV:
        return [Path(p) for p in _PROMPTMAP_PATHS_ENV.split(":") if p.strip()]
    return list(SOURCE_DIR.rglob("PROMPTMAP.yaml"))


def _load_promptmap(path: Path) -> dict:
    import yaml as _yaml
    with path.open() as f:
        return _yaml.safe_load(f) or {}


def _save_promptmap(path: Path, data: dict) -> None:
    import yaml as _yaml
    with path.open("w") as f:
        _yaml.dump(data, f, allow_unicode=True, default_flow_style=False, sort_keys=False)


def _promptmap_repo_name(path: Path) -> str:
    """Derive a short repo name from PROMPTMAP path (parent directory names)."""
    parts = path.parts
    try:
        ai_idx = list(parts).index("ai")
        return parts[ai_idx - 1] if ai_idx > 0 else path.parent.parent.name
    except ValueError:
        return path.parent.parent.name


def _iter_tasks(data: dict, sprint: Optional[int] = None):
    """Yield (sprint_num, task_dict) pairs from a PROMPTMAP data structure."""
    version = data.get("version", 1)
    if version >= 2:
        # v2: top-level entries list + sprint blocks
        for entry in data.get("entries", []):
            yield None, entry
        for block in data.get("sprints", []):
            snum = block.get("sprint")
            for task in block.get("tasks", []):
                if sprint is None or snum == sprint:
                    yield snum, task
        # v2 can also have top-level sprint + tasks (single sprint file)
        if "sprint" in data and "tasks" in data:
            snum = data["sprint"]
            for task in data["tasks"]:
                if sprint is None or snum == sprint:
                    yield snum, task
    else:
        for task in data.get("tasks", []):
            yield None, task


@mcp.tool()
def list_tasks(
    repo: str = "",
    sprint: Optional[int] = None,
    status: Optional[str] = None,
) -> list[dict]:
    """List tasks from PROMPTMAP.yaml files.

    Args:
        repo: Filter by repo name substring (e.g. 'CIC-Relay'). Empty = all repos.
        sprint: Filter by sprint number. None = all sprints.
        status: Filter by status ('todo', 'done', 'in_progress', 'failed'). None = all.

    Returns list of dicts with keys: repo, sprint, task, status, priority, prompt (truncated).
    """
    results = []
    for pm_path in _find_promptmaps():
        repo_name = _promptmap_repo_name(pm_path)
        if repo and repo.lower() not in repo_name.lower():
            continue
        try:
            data = _load_promptmap(pm_path)
        except Exception as e:
            results.append({"repo": repo_name, "error": str(e)})
            continue
        for snum, task in _iter_tasks(data, sprint):
            if not isinstance(task, dict):
                continue
            task_status = task.get("status", "")
            if status and task_status != status:
                continue
            prompt_text = str(task.get("prompt", ""))
            results.append({
                "repo": repo_name,
                "sprint": snum,
                "task": task.get("task", ""),
                "status": task_status,
                "priority": task.get("priority"),
                "milestone": task.get("milestone"),
                "prompt": prompt_text[:200] + "..." if len(prompt_text) > 200 else prompt_text,
                "accept": task.get("accept", ""),
                "tests": task.get("tests", []),
            })
    results.sort(key=lambda x: (x.get("priority") is None, x.get("priority") or 0))
    return results


@mcp.tool()
def get_next_task(repo: str = "", sprint: Optional[int] = None) -> Optional[dict]:
    """Return the highest-priority todo task from PROMPTMAP files.

    Args:
        repo: Filter by repo name substring.
        sprint: Filter by sprint number. None = any sprint.

    Returns the full task dict (with prompt, tests, accept) or None if no todo tasks found.
    """
    tasks = list_tasks(repo=repo, sprint=sprint, status="todo")
    if not tasks:
        return None
    # Already sorted by priority
    t = tasks[0]
    # Re-read full prompt (list_tasks truncates it)
    for pm_path in _find_promptmaps():
        repo_name = _promptmap_repo_name(pm_path)
        if t["repo"] != repo_name:
            continue
        try:
            data = _load_promptmap(pm_path)
        except Exception:
            continue
        for snum, task in _iter_tasks(data):
            if task.get("task") == t["task"] and task.get("status") == "todo":
                return {
                    "repo": repo_name,
                    "sprint": snum,
                    **{k: v for k, v in task.items()},
                }
    return t


def _update_task_status(pm_path: Path, task_id: str, new_status: str, extra: Optional[dict] = None) -> bool:
    """Mutate a task's status in a PROMPTMAP file. Returns True if found and saved."""
    import yaml as _yaml
    data = _load_promptmap(pm_path)
    found = False

    def _patch(task: dict) -> None:
        nonlocal found
        if task.get("task") == task_id:
            task["status"] = new_status
            if extra:
                task.update(extra)
            found = True

    for entry in data.get("entries", []):
        if isinstance(entry, dict):
            _patch(entry)
    for block in data.get("sprints", []):
        for task in block.get("tasks", []):
            if isinstance(task, dict):
                _patch(task)
    if "tasks" in data:
        for task in data["tasks"]:
            if isinstance(task, dict):
                _patch(task)

    if found:
        _save_promptmap(pm_path, data)
    return found


@mcp.tool()
def claim_task(task_id: str, repo: str = "") -> dict:
    """Mark a task as in_progress in the PROMPTMAP.

    Args:
        task_id: The task identifier string (e.g. 'upstream-source-http').
        repo: Repo name substring to narrow the search (optional).

    Returns: {success, repo, task_id, message}
    """
    for pm_path in _find_promptmaps():
        repo_name = _promptmap_repo_name(pm_path)
        if repo and repo.lower() not in repo_name.lower():
            continue
        if _update_task_status(pm_path, task_id, "in_progress"):
            return {"success": True, "repo": repo_name, "task_id": task_id, "message": "status → in_progress"}
    return {"success": False, "task_id": task_id, "message": "task not found"}


@mcp.tool()
def complete_task(task_id: str, repo: str = "", result_note: str = "") -> dict:
    """Mark a task as done in the PROMPTMAP.

    Args:
        task_id: The task identifier string.
        repo: Repo name substring to narrow the search (optional).
        result_note: Short summary of what was done (stored as 'result' field).

    Returns: {success, repo, task_id, message}
    """
    extra = {"result": result_note} if result_note else None
    for pm_path in _find_promptmaps():
        repo_name = _promptmap_repo_name(pm_path)
        if repo and repo.lower() not in repo_name.lower():
            continue
        if _update_task_status(pm_path, task_id, "done", extra):
            return {"success": True, "repo": repo_name, "task_id": task_id, "message": "status → done"}
    return {"success": False, "task_id": task_id, "message": "task not found"}


@mcp.tool()
def fail_task(task_id: str, reason: str, repo: str = "") -> dict:
    """Mark a task as failed in the PROMPTMAP with a reason.

    Args:
        task_id: The task identifier string.
        reason: Why it failed (stored as 'failure_reason' field).
        repo: Repo name substring to narrow the search (optional).

    Returns: {success, repo, task_id, message}
    """
    for pm_path in _find_promptmaps():
        repo_name = _promptmap_repo_name(pm_path)
        if repo and repo.lower() not in repo_name.lower():
            continue
        if _update_task_status(pm_path, task_id, "failed", {"failure_reason": reason}):
            return {"success": True, "repo": repo_name, "task_id": task_id, "message": "status → failed"}
    return {"success": False, "task_id": task_id, "message": "task not found"}


@mcp.tool()
def update_companion(
    file_path: str,
    description: str = "",
    category: Optional[list] = None,
    used_in: Optional[list] = None,
    related_nodes: Optional[list] = None,
    tags: Optional[list] = None,
) -> dict:
    """Update semantic fields in a companion YAML file (Go meta companion).

    Only updates fields that are explicitly provided (non-empty/non-None).
    Auto-generated fields (package, objects, references) are never touched.
    After updating, the file must be committed (Vault Transit hook signs it automatically).

    Args:
        file_path: Absolute path or path relative to SOURCE_DIR to the companion .yaml.
        description: Package-level description (replaces empty description only if provided).
        category: List of category tags (replaces existing list if provided).
        used_in: List of usage contexts (replaces existing list if provided).
        related_nodes: List of related node IDs (replaces existing list if provided).
        tags: List of keyword tags (replaces existing list if provided).

    Returns: {success, path, updated_fields, message}
    """
    import yaml as _yaml

    p = Path(file_path)
    if not p.is_absolute():
        p = SOURCE_DIR / file_path
    if not p.exists():
        return {"success": False, "path": str(p), "message": "file not found"}

    try:
        with p.open() as f:
            data = _yaml.safe_load(f) or {}
    except Exception as e:
        return {"success": False, "path": str(p), "message": f"parse error: {e}"}

    updated: list[str] = []

    if description:
        data["description"] = description
        updated.append("description")
    if category is not None:
        data["category"] = category
        updated.append("category")
    if used_in is not None:
        data["used_in"] = used_in
        updated.append("used_in")
    if related_nodes is not None:
        data["related_nodes"] = related_nodes
        updated.append("related_nodes")
    if tags is not None:
        data["tags"] = tags
        updated.append("tags")

    if not updated:
        return {"success": False, "path": str(p), "message": "no fields to update provided"}

    try:
        with p.open("w") as f:
            _yaml.dump(data, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
    except Exception as e:
        return {"success": False, "path": str(p), "message": f"write error: {e}"}

    return {
        "success": True,
        "path": str(p),
        "updated_fields": updated,
        "message": f"Updated {len(updated)} field(s). Commit to trigger Vault Transit signing.",
    }


@mcp.tool()
def record_decision(
    node_id: str,
    decision: str,
    rationale: str = "",
    companion_path: str = "",
) -> dict:
    """Record an agent decision as a note in a companion YAML or standalone decision file.

    Appends a decision entry to the companion YAML's 'agent_decisions' list.
    If no companion_path given, tries to find the companion by node_id lookup.

    Args:
        node_id: KB node ID this decision relates to.
        decision: Short statement of the decision made.
        rationale: Why this decision was made (optional).
        companion_path: Explicit path to companion YAML. If empty, resolved from node_id.

    Returns: {success, path, message}
    """
    import yaml as _yaml
    from datetime import datetime, timezone

    kb = load_kb()

    # Resolve companion path from node if not given
    p: Optional[Path] = None
    if companion_path:
        p = Path(companion_path)
        if not p.is_absolute():
            p = SOURCE_DIR / companion_path
    else:
        node = kb["nodes"].get(str(node_id))
        if node:
            src = node.get("source_file") or node.get("file_path") or ""
            if src:
                candidate = Path(src).with_suffix(".yaml")
                if candidate.exists():
                    p = candidate
                else:
                    candidate2 = SOURCE_DIR / src
                    candidate2 = candidate2.with_suffix(".yaml")
                    if candidate2.exists():
                        p = candidate2

    if p is None or not p.exists():
        return {
            "success": False,
            "node_id": node_id,
            "message": "companion file not found — provide companion_path explicitly",
        }

    try:
        with p.open() as f:
            data = _yaml.safe_load(f) or {}
    except Exception as e:
        return {"success": False, "path": str(p), "message": f"parse error: {e}"}

    decisions = data.setdefault("agent_decisions", [])
    entry: dict = {
        "node_id": node_id,
        "decision": decision,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if rationale:
        entry["rationale"] = rationale
    decisions.append(entry)

    try:
        with p.open("w") as f:
            _yaml.dump(data, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
    except Exception as e:
        return {"success": False, "path": str(p), "message": f"write error: {e}"}

    return {
        "success": True,
        "path": str(p),
        "message": f"Decision recorded in agent_decisions[{len(decisions)-1}]. Commit to persist.",
    }


DEFAULT_HOST = os.environ.get("MCP_HOST", "127.0.0.1")
DEFAULT_PORT = int(os.environ.get("MCP_PORT", "8000"))


def main() -> None:
    global _watch_dir, _watch_interval

    parser = argparse.ArgumentParser(description="CIC Graph MCP Server")
    parser.add_argument("--sse", action="store_true", help="Run as SSE server")
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"SSE bind host (default: {DEFAULT_HOST}, env: MCP_HOST)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"SSE bind port (default: {DEFAULT_PORT}, env: MCP_PORT)")
    parser.add_argument("--watch-dir", metavar="DIR",
                        default=os.environ.get("KB_WATCH_DIR", str(Path.cwd())),
                        help="Watch this directory for file changes and update KB in-memory (default: cwd, env: KB_WATCH_DIR)")
    parser.add_argument("--watch-interval", type=float, default=float(os.environ.get("KB_WATCH_INTERVAL", "2")),
                        help="Poll interval for --watch-dir in seconds (default: 2, env: KB_WATCH_INTERVAL)")
    args = parser.parse_args()

    if args.watch_dir:
        _watch_dir = Path(args.watch_dir).resolve()
        _watch_interval = args.watch_interval
        # Build initial KB from source if chunks.pkl is missing
        if not CHUNKS_PKL.exists():
            print(f"[watch] chunks.pkl not found — building initial KB from {_watch_dir} ...", flush=True)
            _bootstrap_kb_from_source(_watch_dir)
        # Pre-load KB so the embedding model is in memory before the watcher starts
        load_kb()
        t = threading.Thread(target=_watch_loop, daemon=True, name="kb-watcher")
        t.start()

    if args.sse:
        print(f"Starting SSE server on http://{args.host}:{args.port}")
        mcp.settings.host = args.host
        mcp.settings.port = args.port
        mcp.run(transport="sse")
    else:
        mcp.run()


if __name__ == "__main__":
    main()
