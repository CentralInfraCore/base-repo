import os
import sys
import pickle
import tempfile
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from make_source import (
    build_bm25_index,
    build_faiss_index,
    create_bm25_inverted_index,
    create_knowledge_graph_with_content,
    process_md_file,
    process_yaml_file,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_CHUNKS = [
    {"id": "c1", "text": "A Relay kezeli a hostokat és a szolgáltatásokat.", "file_path": "docs/relay.md", "section": "Relay", "start_line": 1, "end_line": 5, "lang": "hu", "type": "section"},
    {"id": "c2", "text": "A Host a futtató környezet, VM vagy fizikai gép.", "file_path": "docs/host.md", "section": "Host", "start_line": 1, "end_line": 5, "lang": "hu", "type": "section"},
    {"id": "c3", "text": "The Service is a functional unit that produces value.", "file_path": "docs/service.md", "section": "Service", "start_line": 1, "end_line": 5, "lang": "en", "type": "section"},
    {"id": "c4", "text": "Vault Transit engine signs artifacts with ECDSA SHA256.", "file_path": "docs/vault.md", "section": "Vault", "start_line": 1, "end_line": 5, "lang": "en", "type": "section"},
    {"id": "c5", "text": "A Relay és a Host kapcsolata gráf-alapú, nem fa struktúra.", "file_path": "docs/relay.md", "section": "Graph", "start_line": 6, "end_line": 10, "lang": "hu", "type": "section"},
]


# ---------------------------------------------------------------------------
# build_bm25_index
# ---------------------------------------------------------------------------

class TestBuildBm25Index:
    def test_returns_bm25_object(self):
        from rank_bm25 import BM25Okapi
        bm25 = build_bm25_index(SAMPLE_CHUNKS)
        assert isinstance(bm25, BM25Okapi)

    def test_scores_relevant_chunk_higher(self):
        bm25 = build_bm25_index(SAMPLE_CHUNKS)
        scores = bm25.get_scores(["relay"])
        # c1 and c5 mention "relay" (lowercased), should score > 0
        assert scores[0] > 0 or scores[4] > 0

    def test_scores_length_matches_chunks(self):
        bm25 = build_bm25_index(SAMPLE_CHUNKS)
        scores = bm25.get_scores(["host"])
        assert len(scores) == len(SAMPLE_CHUNKS)

    def test_empty_text_does_not_raise(self):
        from rank_bm25 import BM25Okapi
        bm25 = build_bm25_index([{"id": "c1", "text": ""}])
        assert isinstance(bm25, BM25Okapi)


# ---------------------------------------------------------------------------
# build_faiss_index
# ---------------------------------------------------------------------------

class TestBuildFaissIndex:
    def test_returns_faiss_index(self):
        import faiss
        embeddings = np.random.rand(5, 64).astype("float32")
        # normalize
        norms = np.linalg.norm(embeddings, axis=1, keepdims=True)
        embeddings /= norms
        index = build_faiss_index(embeddings)
        assert isinstance(index, faiss.IndexFlatIP)

    def test_index_contains_all_vectors(self):
        embeddings = np.random.rand(5, 64).astype("float32")
        norms = np.linalg.norm(embeddings, axis=1, keepdims=True)
        embeddings /= norms
        index = build_faiss_index(embeddings)
        assert index.ntotal == 5

    def test_search_returns_top_k(self):
        dim = 64
        embeddings = np.random.rand(5, dim).astype("float32")
        norms = np.linalg.norm(embeddings, axis=1, keepdims=True)
        embeddings /= norms
        index = build_faiss_index(embeddings)
        query = embeddings[0:1]
        scores, indices = index.search(query, 3)
        assert scores.shape == (1, 3)
        assert indices.shape == (1, 3)

    def test_self_similarity_is_highest(self):
        dim = 64
        embeddings = np.random.rand(5, dim).astype("float32")
        norms = np.linalg.norm(embeddings, axis=1, keepdims=True)
        embeddings /= norms
        index = build_faiss_index(embeddings)
        # query with the first vector — it should be the top hit
        query = embeddings[0:1]
        _, indices = index.search(query, 1)
        assert indices[0][0] == 0


# ---------------------------------------------------------------------------
# create_bm25_inverted_index
# ---------------------------------------------------------------------------

class TestCreateBm25InvertedIndex:
    def test_returns_dict(self):
        bm25 = build_bm25_index(SAMPLE_CHUNKS)
        inv = create_bm25_inverted_index(SAMPLE_CHUNKS, bm25)
        assert isinstance(inv, dict)

    def test_contains_known_token(self):
        bm25 = build_bm25_index(SAMPLE_CHUNKS)
        inv = create_bm25_inverted_index(SAMPLE_CHUNKS, bm25)
        assert "relay" in inv or "host" in inv

    def test_entries_have_chunk_id_and_score(self):
        bm25 = build_bm25_index(SAMPLE_CHUNKS)
        inv = create_bm25_inverted_index(SAMPLE_CHUNKS, bm25)
        for token, entries in inv.items():
            for entry in entries:
                assert "chunk_id" in entry
                assert "score" in entry
                assert entry["score"] > 0.01

    def test_entries_sorted_by_score_descending(self):
        bm25 = build_bm25_index(SAMPLE_CHUNKS)
        inv = create_bm25_inverted_index(SAMPLE_CHUNKS, bm25)
        for token, entries in inv.items():
            scores = [e["score"] for e in entries]
            assert scores == sorted(scores, reverse=True)


# ---------------------------------------------------------------------------
# create_knowledge_graph_with_content
# ---------------------------------------------------------------------------

class TestCreateKnowledgeGraph:
    def _make_embeddings(self, n=5, dim=64):
        emb = np.random.rand(n, dim).astype("float32")
        norms = np.linalg.norm(emb, axis=1, keepdims=True)
        return emb / norms

    def test_returns_nodes_and_edges(self):
        embeddings = self._make_embeddings()
        nodes, edges = create_knowledge_graph_with_content(SAMPLE_CHUNKS, embeddings)
        assert len(nodes) == len(SAMPLE_CHUNKS)
        assert len(edges) > 0

    def test_node_ids_sequential(self):
        embeddings = self._make_embeddings()
        nodes, _ = create_knowledge_graph_with_content(SAMPLE_CHUNKS, embeddings)
        ids = [n["id"] for n in nodes]
        assert ids == [f"n{i+1}" for i in range(len(SAMPLE_CHUNKS))]

    def test_nodes_have_chunk_ids(self):
        embeddings = self._make_embeddings()
        nodes, _ = create_knowledge_graph_with_content(SAMPLE_CHUNKS, embeddings)
        chunk_ids = {n["chunk_id"] for n in nodes}
        assert chunk_ids == {c["id"] for c in SAMPLE_CHUNKS}

    def test_refers_to_edges_sequential(self):
        embeddings = self._make_embeddings()
        _, edges = create_knowledge_graph_with_content(SAMPLE_CHUNKS, embeddings)
        refers_to = [e for e in edges if e["type"] == "refers-to"]
        assert len(refers_to) == len(SAMPLE_CHUNKS) - 1

    def test_related_to_edges_high_similarity(self):
        # Force high cosine similarity between first two vectors
        dim = 64
        base = np.random.rand(dim).astype("float32")
        base /= np.linalg.norm(base)
        embeddings = np.tile(base, (5, 1))
        # add tiny noise so they're not identical
        embeddings += np.random.rand(5, dim).astype("float32") * 0.001
        norms = np.linalg.norm(embeddings, axis=1, keepdims=True)
        embeddings /= norms
        _, edges = create_knowledge_graph_with_content(SAMPLE_CHUNKS, embeddings)
        related = [e for e in edges if e["type"] == "related-to"]
        assert len(related) > 0

    def test_edge_ids_unique(self):
        embeddings = self._make_embeddings()
        _, edges = create_knowledge_graph_with_content(SAMPLE_CHUNKS, embeddings)
        ids = [e["id"] for e in edges]
        assert len(ids) == len(set(ids))


# ---------------------------------------------------------------------------
# process_md_file / process_yaml_file
# ---------------------------------------------------------------------------

class TestFileProcessors:
    def test_process_md_file_returns_chunks(self, tmp_path):
        md = tmp_path / "test.md"
        md.write_text("# Section One\nContent here.\n\n## Section Two\nMore content.\n")
        chunks = process_md_file(str(md))
        assert len(chunks) >= 2
        assert all("text" in c and "file_path" in c for c in chunks)

    def test_process_md_file_sets_file_path(self, tmp_path):
        md = tmp_path / "test.md"
        md.write_text("# Title\nBody text.\n")
        chunks = process_md_file(str(md))
        assert all(c["file_path"] == str(md) for c in chunks)

    def test_process_yaml_file_returns_chunk(self, tmp_path):
        yml = tmp_path / "test.yaml"
        yml.write_text("key: value\nnested:\n  a: 1\n")
        chunks = process_yaml_file(str(yml))
        assert len(chunks) == 1
        assert chunks[0]["type"] == "yaml_file"

    def test_process_yaml_file_invalid_returns_empty(self, tmp_path):
        bad = tmp_path / "bad.yaml"
        bad.write_text(": invalid: yaml: [\n")
        chunks = process_yaml_file(str(bad))
        assert chunks == []


# ---------------------------------------------------------------------------
# create_embeddings (mocked — no model download in tests)
# ---------------------------------------------------------------------------

class TestCreateEmbeddings:
    def test_returns_model_and_ndarray(self):
        mock_model = MagicMock()
        mock_model.encode.return_value = np.random.rand(5, 384).astype("float32")

        with patch("make_source.SentenceTransformer", return_value=mock_model):
            from make_source import create_embeddings
            model, embeddings = create_embeddings(["text"] * 5)

        assert isinstance(embeddings, np.ndarray)
        assert embeddings.shape == (5, 384)
        assert embeddings.dtype == np.float32

    def test_encode_called_with_normalize(self):
        mock_model = MagicMock()
        mock_model.encode.return_value = np.random.rand(3, 384).astype("float32")

        with patch("make_source.SentenceTransformer", return_value=mock_model):
            from make_source import create_embeddings
            create_embeddings(["a", "b", "c"])

        call_kwargs = mock_model.encode.call_args[1]
        assert call_kwargs.get("normalize_embeddings") is True
