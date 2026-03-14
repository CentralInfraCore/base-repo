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
import numpy as np
import faiss
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP
from sentence_transformers import SentenceTransformer

mcp = FastMCP("cic-graph")

# Adjust paths to point to the correct location relative to this script
BASE_DIR = Path(__file__).parent.parent
DATA_DIR = Path(os.environ.get("KB_DATA_DIR", str(BASE_DIR / "kb_data" / "pkl")))

CHUNKS_PKL = Path(os.environ.get("CHUNKS_PKL", str(DATA_DIR / "chunks.pkl")))
NODES_PKL = Path(os.environ.get("NODES_PKL", str(DATA_DIR / "graph_nodes.pkl")))
EDGES_PKL = Path(os.environ.get("EDGES_PKL", str(DATA_DIR / "graph_edges.pkl")))
INVERTED_PKL = Path(os.environ.get("INVERTED_PKL", str(DATA_DIR / "inverted_index.pkl")))
FAISS_INDEX = Path(os.environ.get("FAISS_INDEX", str(DATA_DIR / "faiss.index")))
BM25_PKL = Path(os.environ.get("BM25_PKL", str(DATA_DIR / "bm25.pkl")))
CHUNK_IDS_PKL = Path(os.environ.get("CHUNK_IDS_PKL", str(DATA_DIR / "chunk_ids.pkl")))
MODEL_NAME_PKL = Path(os.environ.get("MODEL_NAME_PKL", str(DATA_DIR / "model_name.pkl")))

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


@lru_cache(maxsize=1)
def load_kb() -> dict[str, Any]:
    """Load all PKL artifacts into memory once."""
    def load_one(p: Path) -> Any:
        if not p.exists():
            raise FileNotFoundError(f"Missing: {p}")
        with p.open("rb") as f:
            return pickle.load(f)

    chunks = load_one(CHUNKS_PKL)
    nodes = load_one(NODES_PKL)
    edges = load_one(EDGES_PKL)
    inverted = load_one(INVERTED_PKL)

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
    embedding_model = SentenceTransformer(model_name) if faiss_idx is not None else None

    return {
        "chunks": chunks_by_id,
        "nodes": nodes_by_id,
        "edges": edges_list,
        "adj": adj,
        "chunk_to_nodes": chunk_to_nodes,
        "inverted": inverted_index,
        "faiss_index": faiss_idx,
        "faiss_chunk_ids": faiss_chunk_ids,
        "bm25": bm25,
        "embedding_model": embedding_model,
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


def _extract_chunk_file_path(chunk: dict) -> str:
    meta = chunk.get("metadata", {})
    if not isinstance(meta, dict):
        meta = {}
    return str(
        chunk.get("file_path")
        or meta.get("file_path")
        or chunk.get("path")
        or meta.get("path")
        or ""
    )


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
    return {
        "data_dir": str(DATA_DIR),
        "cache_info": load_kb.cache_info()._asdict(),
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
    Useful after regenerating PKL files.
    """
    before = _kb_mtimes()
    load_kb.cache_clear()
    kb = load_kb()
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
                "file_path": chunk.get("file_path") or meta.get("file_path"),
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
            "file_path": chunk.get("file_path") or meta.get("file_path"),
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
                "file_path": file_path,
                "line_range": line_range
            })
            if len(results) >= limit:
                break

    return results


@mcp.tool()
def search_nodes(query: str, limit: int = 10) -> list[dict]:
    """Search for nodes by name, label, type, or tags.

    Useful when you know the concept name but not the exact text content.
    """
    kb = load_kb()
    q = query.lower().strip()
    results = []
    limit = _clamp_topk(limit)

    for nid, node in kb["nodes"].items():
        if not isinstance(node, dict):
            continue

        score = 0
        # Check ID
        if q in str(nid).lower():
            score += 4
        # Check Label/Name
        label = str(node.get("label") or node.get("name") or "")
        if q in label.lower():
            score += 3
        # Check Type/Category
        cat = str(node.get("type") or node.get("category") or "")
        if q in cat.lower():
            score += 2
        # Check Tags
        tags = node.get("tags") or []
        if isinstance(tags, list):
            for t in tags:
                if q in str(t).lower():
                    score += 1
                    break

        if score > 0:
            results.append({
                "node_id": nid,
                "score": score,
                "label": label,
                "type": cat,
                "chunk_id": node.get("chunk_id")
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

        # Check path match
        path_raw = (
            chunk.get("file_path") or
            meta.get("file_path") or
            chunk.get("path") or
            meta.get("path") or ""
        )
        path_str = str(path_raw).lower()

        match = False
        if mode == "exact":
            match = (path_str == target)
        elif mode == "contains":
            match = (target in path_str)
        else: # prefix (default)
            match = path_str.startswith(target)

        if match:
            raw_lines = (
                chunk.get("line_range") or
                meta.get("line_range") or
                chunk.get("lines") or
                meta.get("lines")
            )
            line_range = _normalize_line_range(raw_lines)

            results.append({
                "chunk_id": cid,
                "file_path": path_raw,
                "line_range": line_range
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
def focus_pack(query: str, depth: int = 1, limit: int = 5, max_rules: int = 3) -> dict:
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
    limit = max(1, min(int(limit), MAX_TOPK))
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
    limit: int = 50,
) -> list[dict]:
    """Filter nodes by metadata (if present).

    Expects node payload to possibly contain fields like:
    - category (str or list)
    - tags (list[str])
    - used_in (list[str] or str)
    """
    kb = load_kb()
    out: list[dict] = []
    cat = category.lower() if category else None
    tg = tag.lower() if tag else None
    ui = used_in.lower() if used_in else None

    for n in kb["nodes"].values():
        if not isinstance(n, dict):
            continue

        if cat:
            v = n.get("category")
            ok = (isinstance(v, str) and v.lower() == cat) or (isinstance(v, list) and any(str(x).lower() == cat for x in v))
            if not ok:
                continue

        if tg:
            v = n.get("tags") or []
            if isinstance(v, str):
                v = [v]
            if not (isinstance(v, list) and any(str(x).lower() == tg for x in v)):
                continue

        if ui:
            v = n.get("used_in") or []
            if isinstance(v, str):
                v = [v]
            if not (isinstance(v, list) and any(str(x).lower() == ui for x in v)):
                continue

        out.append(n)
        if len(out) >= _clamp_topk(limit):
            break

    return out


DEFAULT_HOST = os.environ.get("MCP_HOST", "127.0.0.1")
DEFAULT_PORT = int(os.environ.get("MCP_PORT", "8000"))


def main() -> None:
    parser = argparse.ArgumentParser(description="CIC Graph MCP Server")
    parser.add_argument("--sse", action="store_true", help="Run as SSE server")
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"SSE bind host (default: {DEFAULT_HOST}, env: MCP_HOST)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"SSE bind port (default: {DEFAULT_PORT}, env: MCP_PORT)")
    args = parser.parse_args()

    if args.sse:
        print(f"Starting SSE server on http://{args.host}:{args.port}")
        mcp.run(transport="sse", host=args.host, port=args.port)
    else:
        mcp.run()


if __name__ == "__main__":
    main()
