import os
import sys
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../mcp-server")))

import server as mcp_server

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_faiss_index(n=5, dim=64):
    import faiss
    embeddings = np.random.rand(n, dim).astype("float32")
    norms = np.linalg.norm(embeddings, axis=1, keepdims=True)
    embeddings /= norms
    index = faiss.IndexFlatIP(dim)
    index.add(embeddings)
    return index, embeddings


def _make_bm25(texts):
    from rank_bm25 import BM25Okapi
    return BM25Okapi([t.lower().split() for t in texts])


SAMPLE_CHUNKS = {
    "c1": {"id": "c1", "text": "Relay manages hosts and services.", "file_path": "docs/relay.md", "section": "Relay", "start_line": 1, "end_line": 5, "lang": "en", "type": "section"},
    "c2": {"id": "c2", "text": "Host is the execution environment.", "file_path": "docs/host.md", "section": "Host", "start_line": 1, "end_line": 5, "lang": "en", "type": "section"},
    "c3": {"id": "c3", "text": "Vault signs artifacts with ECDSA.", "file_path": "docs/vault.md", "section": "Vault", "start_line": 1, "end_line": 5, "lang": "en", "type": "section"},
    "c4": {"id": "c4", "text": "Service produces value for the system.", "file_path": "docs/service.md", "section": "Service", "start_line": 1, "end_line": 5, "lang": "en", "type": "section"},
    "c5": {"id": "c5", "text": "Graph-based model for relay and host.", "file_path": "docs/graph.md", "section": "Graph", "start_line": 1, "end_line": 5, "lang": "en", "type": "section"},
}

CHUNK_IDS = ["c1", "c2", "c3", "c4", "c5"]
CHUNK_TEXTS = [SAMPLE_CHUNKS[cid]["text"] for cid in CHUNK_IDS]


def _make_kb(with_faiss=True, with_bm25=True):
    """Build a minimal KB dict for testing."""
    faiss_idx, embeddings = _make_faiss_index(n=5, dim=64)
    bm25 = _make_bm25(CHUNK_TEXTS)

    mock_model = MagicMock()

    def encode_side_effect(texts, normalize_embeddings=True, **kwargs):
        vec = np.random.rand(len(texts), 64).astype("float32")
        if normalize_embeddings:
            norms = np.linalg.norm(vec, axis=1, keepdims=True)
            vec /= norms
        return vec

    mock_model.encode.side_effect = encode_side_effect

    return {
        "chunks": SAMPLE_CHUNKS,
        "nodes": {},
        "edges": [],
        "adj": {},
        "chunk_to_nodes": {},
        "inverted": {
            "relay": [{"chunk_id": "c1", "score": 0.8}, {"chunk_id": "c5", "score": 0.6}],
            "host":  [{"chunk_id": "c2", "score": 0.9}],
            "vault": [{"chunk_id": "c3", "score": 0.95}],
        },
        "faiss_index": faiss_idx if with_faiss else None,
        "faiss_chunk_ids": CHUNK_IDS if with_faiss else [],
        "bm25": bm25 if with_bm25 else None,
        "embedding_model": mock_model if with_faiss else None,
    }


# ---------------------------------------------------------------------------
# search_query — semantic (FAISS)
# ---------------------------------------------------------------------------

class TestSearchQuerySemantic:
    def test_returns_list(self):
        import server as mcp_server
        kb = _make_kb(with_faiss=True)
        with patch.object(mcp_server, "load_kb", return_value=kb):
            results = mcp_server.search_query("relay management", top_k=3)
        assert isinstance(results, list)

    def test_returns_at_most_top_k(self):
        import server as mcp_server
        kb = _make_kb(with_faiss=True)
        with patch.object(mcp_server, "load_kb", return_value=kb):
            results = mcp_server.search_query("relay", top_k=2)
        assert len(results) <= 2

    def test_result_has_required_fields(self):
        import server as mcp_server
        kb = _make_kb(with_faiss=True)
        with patch.object(mcp_server, "load_kb", return_value=kb):
            results = mcp_server.search_query("vault signing", top_k=3)
        for r in results:
            assert "chunk_id" in r
            assert "score" in r
            assert "file_path" in r

    def test_chunk_ids_are_valid(self):
        import server as mcp_server
        kb = _make_kb(with_faiss=True)
        with patch.object(mcp_server, "load_kb", return_value=kb):
            results = mcp_server.search_query("host environment", top_k=5)
        for r in results:
            assert r["chunk_id"] in SAMPLE_CHUNKS

    def test_threshold_filters_low_scores(self):
        import server as mcp_server
        kb = _make_kb(with_faiss=True)
        with patch.object(mcp_server, "load_kb", return_value=kb):
            results = mcp_server.search_query("relay", top_k=5, threshold=0.99)
        # with very high threshold, likely 0 or very few results
        for r in results:
            assert r["score"] >= 0.99


# ---------------------------------------------------------------------------
# search_query — fallback (no FAISS)
# ---------------------------------------------------------------------------

class TestSearchQueryFallback:
    def test_falls_back_to_inverted_index(self):
        import server as mcp_server
        kb = _make_kb(with_faiss=False, with_bm25=False)
        with patch.object(mcp_server, "load_kb", return_value=kb):
            results = mcp_server.search_query("relay", top_k=5)
        assert len(results) > 0
        cids = [r["chunk_id"] for r in results]
        assert "c1" in cids or "c5" in cids

    def test_empty_query_returns_empty(self):
        import server as mcp_server
        kb = _make_kb(with_faiss=False, with_bm25=False)
        with patch.object(mcp_server, "load_kb", return_value=kb):
            results = mcp_server.search_query("", top_k=5)
        assert results == []


# ---------------------------------------------------------------------------
# search_token — BM25
# ---------------------------------------------------------------------------

class TestSearchTokenBm25:
    def test_returns_list(self):
        import server as mcp_server
        kb = _make_kb(with_bm25=True)
        with patch.object(mcp_server, "load_kb", return_value=kb):
            results = mcp_server.search_token("relay", top_k=3)
        assert isinstance(results, list)

    def test_result_has_chunk_id_and_score(self):
        import server as mcp_server
        kb = _make_kb(with_bm25=True)
        with patch.object(mcp_server, "load_kb", return_value=kb):
            results = mcp_server.search_token("host", top_k=3)
        for r in results:
            assert "chunk_id" in r
            assert "score" in r

    def test_returns_at_most_top_k(self):
        import server as mcp_server
        kb = _make_kb(with_bm25=True)
        with patch.object(mcp_server, "load_kb", return_value=kb):
            results = mcp_server.search_token("relay", top_k=2)
        assert len(results) <= 2

    def test_unknown_token_returns_empty_or_low_scores(self):
        import server as mcp_server
        kb = _make_kb(with_bm25=True)
        with patch.object(mcp_server, "load_kb", return_value=kb):
            results = mcp_server.search_token("xyznotaword123", top_k=5)
        # BM25 returns 0 for unknown tokens, filtered by > 0.01
        assert results == [] or all(r["score"] <= 0.01 for r in results)


# ---------------------------------------------------------------------------
# search_token — fallback (no BM25)
# ---------------------------------------------------------------------------

class TestSearchTokenFallback:
    def test_falls_back_to_inverted_index(self):
        import server as mcp_server
        kb = _make_kb(with_bm25=False)
        with patch.object(mcp_server, "load_kb", return_value=kb):
            results = mcp_server.search_token("vault", top_k=3)
        assert len(results) > 0
        assert results[0]["chunk_id"] == "c3"

    def test_unknown_token_returns_empty(self):
        import server as mcp_server
        kb = _make_kb(with_bm25=False)
        with patch.object(mcp_server, "load_kb", return_value=kb):
            results = mcp_server.search_token("xyznotaword", top_k=3)
        assert results == []
