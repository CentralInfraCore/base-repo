"""Tests for kb_build_info: the provenance record written with every KB build/update.

The unit tests run against real, throw-away git repositories. The integration
tests at the end exercise the two write paths (make_source.build_knowledge_base and
kb_watch.incremental_update); they need the heavy KB dependencies and skip without them.
"""

import os
import subprocess
import sys

import numpy as np
import pytest
import yaml

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

import kb_build_info as kbi  # noqa: E402

# Never run the user's global hooks (they sign commits) or read their git config.
_GIT = [
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "commit.gpgsign=false",
    "-c",
    "user.name=t",
    "-c",
    "user.email=t@example.invalid",
]


def git(repo, *args):
    res = subprocess.run(
        ["git", *_GIT, "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return res.stdout.strip()


def make_repo(path, files=None, tag=None):
    path.mkdir(parents=True, exist_ok=True)
    git(path, "init", "-q", "-b", "main")
    for name, content in (files or {"README.md": "# r\n"}).items():
        (path / name).parent.mkdir(parents=True, exist_ok=True)
        (path / name).write_text(content)
    git(path, "add", "-A")
    git(path, "commit", "-q", "-m", "init")
    if tag:
        git(path, "tag", tag)
    return path


def commit_file(repo, name="more.md", content="x\n", msg="more"):
    (repo / name).write_text(content)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", msg)
    return git(repo, "rev-parse", "HEAD")


# ── collect_sources ──────────────────────────────────────────────────────────


def test_collect_sources_records_commit_branch_and_clean_state(tmp_path):
    repo = make_repo(tmp_path / "src" / "app")
    (row,) = kbi.collect_sources(tmp_path / "src")
    assert row["path"] == "app"
    assert row["commit"] == git(repo, "rev-parse", "HEAD")
    assert row["branch"] == "main"
    assert row["dirty"] is False and row["dirty_files"] == 0
    assert row["tag"] is None
    assert row["remote"] is None and row["project_version"] is None
    assert row["describe"] and row["commit"].startswith(
        row["describe"]
    )  # no tags: abbreviated sha


def test_tag_and_describe_follow_the_checked_out_commit(tmp_path):
    repo = make_repo(
        tmp_path / "src" / "app", tag="schemas@v0.9.0"
    )  # namespaced tags are the norm here
    (row,) = kbi.collect_sources(tmp_path / "src")
    assert row["tag"] == "schemas@v0.9.0" and row["describe"] == "schemas@v0.9.0"

    commit_file(repo)
    (row,) = kbi.collect_sources(tmp_path / "src")
    assert row["tag"] is None
    assert row["describe"].startswith("schemas@v0.9.0-1-g")


def test_detached_head_has_no_branch(tmp_path):
    repo = make_repo(tmp_path / "src" / "app")
    git(repo, "checkout", "-q", "--detach")
    (row,) = kbi.collect_sources(tmp_path / "src")
    assert row["branch"] is None and row["commit"]


def test_dirty_counts_tracked_changes_only(tmp_path):
    repo = make_repo(tmp_path / "src" / "app")
    (repo / "untracked.txt").write_text("u")
    (row,) = kbi.collect_sources(tmp_path / "src")
    assert (
        row["dirty"] is False
    )  # untracked files are not part of the commit comparison

    (repo / "README.md").write_text("changed\n")
    (row,) = kbi.collect_sources(tmp_path / "src")
    assert row["dirty"] is True and row["dirty_files"] == 1


@pytest.mark.parametrize(
    "remote, expected",
    [
        ("https://user:s3cret@github.com/o/r.git", "https://github.com/o/r.git"),
        ("https://oauth2:tok@gitlab.example/o/r.git", "https://gitlab.example/o/r.git"),
        ("git@github.com:o/r.git", "git@github.com:o/r.git"),
        ("https://github.com/o/r.git", "https://github.com/o/r.git"),
    ],
)
def test_remote_never_keeps_credentials(tmp_path, remote, expected):
    repo = make_repo(tmp_path / "src" / "app")
    git(repo, "remote", "add", "origin", remote)
    (row,) = kbi.collect_sources(tmp_path / "src")
    assert row["remote"] == expected
    assert "s3cret" not in yaml.safe_dump(row) and "tok@" not in yaml.safe_dump(row)


def test_project_version_is_read_from_project_yaml(tmp_path):
    make_repo(
        tmp_path / "src" / "a",
        {"project.yaml": "metadata:\n  name: a\n  version: 0.7.3\n"},
    )
    make_repo(
        tmp_path / "src" / "b", {"project.yaml": "metadata: [not, a, mapping\n"}
    )  # broken YAML
    make_repo(tmp_path / "src" / "c", {"project.yaml": "other: 1\n"})
    rows = {r["path"]: r for r in kbi.collect_sources(tmp_path / "src")}
    assert rows["a"]["project_version"] == "0.7.3"
    assert rows["b"]["project_version"] is None
    assert rows["c"]["project_version"] is None


def test_finds_repos_below_plain_directories_sorted_and_skips_noise(tmp_path):
    src = tmp_path / "src"
    make_repo(src / "org" / "zeta")
    make_repo(src / "org" / "alpha")
    make_repo(src / "top")
    make_repo(src / "node_modules" / "dep")  # dependency checkouts are not sources
    make_repo(src / ".hidden" / "x")
    assert [r["path"] for r in kbi.collect_sources(src)] == [
        "org/alpha",
        "org/zeta",
        "top",
    ]


def test_nested_repos_are_reached_through_gitmodules_only(tmp_path):
    src = tmp_path / "src"
    outer = make_repo(src / "outer")
    make_repo(outer / "inner")  # an independent repo inside the work tree
    assert [r["path"] for r in kbi.collect_sources(src)] == [
        "outer"
    ]  # not declared: not walked

    (outer / ".gitmodules").write_text(
        '[submodule "inner"]\n\tpath = inner\n\turl = x\n'
    )
    assert [r["path"] for r in kbi.collect_sources(src)] == ["outer", "outer/inner"]


def test_source_dir_inside_a_repo_reports_that_repo(tmp_path):
    repo = make_repo(tmp_path / "repo", {"docs/a.md": "# a\n"})
    (row,) = kbi.collect_sources(repo / "docs")
    assert row["path"] == "." and row["commit"] == git(repo, "rev-parse", "HEAD")


def test_not_under_git_gives_no_sources(tmp_path):
    (tmp_path / "plain").mkdir()
    (tmp_path / "plain" / "a.md").write_text("# a\n")
    assert kbi.collect_sources(tmp_path / "plain") == []
    assert kbi.collect_sources(tmp_path / "does-not-exist") == []


# ── build_info / write / load ────────────────────────────────────────────────


def test_build_trigger_sets_built_at_and_counts_sources(tmp_path):
    make_repo(tmp_path / "src" / "a")
    make_repo(tmp_path / "src" / "b")
    info = kbi.build_info(
        tmp_path / "src", trigger="build", counts={"chunks": 7}, model_name="m"
    )
    assert info["schema"] == kbi.SCHEMA
    assert info["kb"]["built_at"] == info["kb"]["updated_at"]
    assert info["kb"]["trigger"] == "build" and info["kb"]["embedding_model"] == "m"
    assert info["kb"]["counts"] == {"chunks": 7, "sources": 2}
    assert info["source_root"] == str((tmp_path / "src").resolve())


def test_update_keeps_built_at_and_model_from_the_previous_record(tmp_path):
    make_repo(tmp_path / "src" / "a")
    first = kbi.build_info(tmp_path / "src", trigger="build", model_name="m")
    first["kb"]["built_at"] = "2026-01-01T00:00:00Z"
    again = kbi.build_info(
        tmp_path / "src", trigger="watch", counts={"chunks": 9}, previous=first
    )
    assert again["kb"]["built_at"] == "2026-01-01T00:00:00Z"
    assert again["kb"]["updated_at"] != "2026-01-01T00:00:00Z"
    assert again["kb"]["trigger"] == "watch" and again["kb"]["embedding_model"] == "m"
    # a fresh build starts over even when a previous record exists
    rebuilt = kbi.build_info(tmp_path / "src", trigger="build", previous=first)
    assert rebuilt["kb"]["built_at"] != "2026-01-01T00:00:00Z"


def test_write_and_load_round_trip_leave_no_temp_files(tmp_path):
    make_repo(tmp_path / "src" / "a")
    info = kbi.build_info(tmp_path / "src", trigger="build")
    out = kbi.write(tmp_path / "kb" / "pkl", info)
    assert out == tmp_path / "kb" / "pkl" / kbi.FILE_NAME
    assert kbi.load(tmp_path / "kb" / "pkl") == info
    assert [p.name for p in (tmp_path / "kb" / "pkl").iterdir()] == [kbi.FILE_NAME]


def test_load_rejects_missing_garbage_and_foreign_files(tmp_path):
    assert kbi.load(tmp_path) is None
    (tmp_path / kbi.FILE_NAME).write_text(": : not yaml [")
    assert kbi.load(tmp_path) is None
    (tmp_path / kbi.FILE_NAME).write_text("schema: something-else/v9\nsources: []\n")
    assert kbi.load(tmp_path) is None


def test_write_failure_does_not_leave_a_temp_file(tmp_path, monkeypatch):
    info = {"schema": kbi.SCHEMA, "kb": {}, "sources": []}
    monkeypatch.setattr(
        kbi.os, "replace", lambda *a, **k: (_ for _ in ()).throw(OSError("disk full"))
    )
    with pytest.raises(OSError):
        kbi.write(tmp_path, info)
    assert list(tmp_path.iterdir()) == []


# ── the dataset chunk ────────────────────────────────────────────────────────


def test_meta_chunk_has_a_fixed_id_and_carries_the_commits(tmp_path):
    repo = make_repo(tmp_path / "src" / "app", tag="v1.0.0")
    info = kbi.build_info(tmp_path / "src", trigger="build")
    chunk = kbi.meta_chunk(info)
    assert (
        chunk["id"] == kbi.CHUNK_ID == "c_kb_build_info"
    )  # fixed: replaced on update, never duplicated
    assert chunk["type"] == kbi.CHUNK_TYPE and "build-info" in chunk["tags"]
    assert chunk["text"] == kbi.render_text(info)
    assert git(repo, "rev-parse", "HEAD") in chunk["text"] and "v1.0.0" in chunk["text"]
    assert chunk["file_paths"] == [chunk["file_path"]]
    assert chunk["end_line"] == len(chunk["text"].splitlines())


class _FakeModel:
    def encode(self, texts, **kwargs):
        return np.ones((len(texts), 4), dtype="float64")


def test_upsert_meta_chunk_replaces_instead_of_adding(tmp_path):
    make_repo(tmp_path / "src" / "app")
    chunks, emb = {"c1": {"id": "c1"}}, {}
    for _ in range(3):
        kbi.upsert_meta_chunk(
            chunks, emb, kbi.build_info(tmp_path / "src", trigger="watch"), _FakeModel()
        )
    assert sorted(chunks) == ["c1", kbi.CHUNK_ID]
    assert list(emb) == [kbi.CHUNK_ID] and emb[kbi.CHUNK_ID].dtype == np.float32


def test_upsert_meta_chunk_without_a_model_skips_the_embedding(tmp_path):
    make_repo(tmp_path / "src" / "app")
    chunks, emb = {}, {}
    kbi.upsert_meta_chunk(
        chunks, emb, kbi.build_info(tmp_path / "src", trigger="watch"), None
    )
    assert kbi.CHUNK_ID in chunks and emb == {}


# ── staleness ────────────────────────────────────────────────────────────────


def _state(info):
    return {r["path"]: r for r in kbi.staleness(info)["sources"]}


def test_staleness_current_then_behind_with_the_commit_count(tmp_path):
    repo = make_repo(tmp_path / "src" / "app")
    info = kbi.build_info(tmp_path / "src", trigger="build")
    report = kbi.staleness(info)
    assert report["stale"] is False and _state(info)["app"]["state"] == "current"

    commit_file(repo, "a.md")
    commit_file(repo, "b.md")
    row = _state(info)["app"]
    assert row["state"] == "behind" and row["commits_since"] == 2
    assert (
        kbi.staleness(info)["stale"] is True
        and kbi.staleness(info)["sources_not_current"] == 1
    )


def test_staleness_ahead_when_the_tree_moved_back(tmp_path):
    repo = make_repo(tmp_path / "src" / "app")
    commit_file(repo)
    info = kbi.build_info(tmp_path / "src", trigger="build")
    git(repo, "reset", "-q", "--hard", "HEAD~1")
    row = _state(info)["app"]
    assert row["state"] == "ahead" and row["commits_since"] == -1


def test_staleness_diverged_on_another_branch(tmp_path):
    repo = make_repo(tmp_path / "src" / "app")
    git(repo, "checkout", "-q", "-b", "feature")
    commit_file(repo, "f.md")
    info = kbi.build_info(tmp_path / "src", trigger="build")  # recorded on 'feature'
    git(repo, "checkout", "-q", "main")
    commit_file(repo, "m.md")
    assert _state(info)["app"]["state"] == "diverged"


def test_staleness_unknown_commit_and_missing_path(tmp_path):
    make_repo(tmp_path / "src" / "app")
    info = kbi.build_info(tmp_path / "src", trigger="build")
    info["sources"][0]["commit"] = "deadbeef" * 5
    assert _state(info)["app"]["state"] == "unknown"

    info = kbi.build_info(tmp_path / "src", trigger="build")
    info["sources"][0]["abs_path"] = str(tmp_path / "gone")
    row = _state(info)["app"]
    assert row["state"] == "missing" and row["dirty_now"] is None


def test_staleness_reports_dirty_now(tmp_path):
    repo = make_repo(tmp_path / "src" / "app")
    info = kbi.build_info(tmp_path / "src", trigger="build")
    (repo / "README.md").write_text("edited\n")
    assert _state(info)["app"]["dirty_now"] is True
    assert kbi.staleness(info)["sources_dirty_now"] == 1


def test_upstream_distance_needs_a_fetch_and_says_when_it_last_happened(tmp_path):
    origin = tmp_path / "origin.git"
    origin.mkdir()
    git(origin, "init", "-q", "--bare", "-b", "main")
    seed = make_repo(tmp_path / "seed")
    git(seed, "remote", "add", "origin", str(origin))
    git(seed, "push", "-q", "origin", "main")
    work = tmp_path / "src" / "app"
    subprocess.run(
        ["git", "clone", "-q", str(origin), str(work)], check=True, capture_output=True
    )
    info = kbi.build_info(tmp_path / "src", trigger="build")

    commit_file(seed)  # upstream moves on
    git(seed, "push", "-q", "origin", "main")
    row = _state(info)["app"]
    assert row["upstream_ref"] == "origin/main"
    assert (
        row["behind_upstream"] == 0
    ), "nothing fetched yet: the local refs cannot know"
    assert (
        row["upstream_fetched_at"] is None
    ), "...and that is exactly what the missing fetch time tells"

    git(work, "fetch", "-q")
    row = _state(info)["app"]
    assert row["behind_upstream"] == 1 and row["upstream_fetched_at"].endswith("Z")
    assert (
        row["state"] == "current"
    ), "being behind upstream is not the KB being behind the tree"
    report = kbi.staleness(info)
    assert report["stale"] is False and report["sources_behind_upstream"] == 1


def test_no_remote_means_no_upstream_information(tmp_path):
    make_repo(tmp_path / "src" / "app")
    info = kbi.build_info(tmp_path / "src", trigger="build")
    row = _state(info)["app"]
    assert (
        row["upstream_ref"] is None
        and row["behind_upstream"] is None
        and row["upstream_fetched_at"] is None
    )
    assert kbi.staleness(info)["sources_behind_upstream"] == 0


def test_status_section_carries_the_upstream_fields(tmp_path):
    make_repo(tmp_path / "src" / "app")
    section = kbi.status_section(
        kbi.build_info(tmp_path / "src", trigger="build"), "file"
    )
    assert section["sources_behind_upstream"] == 0
    assert {"behind_upstream", "upstream_fetched_at"} <= set(section["sources"][0])


# ── kb_status section ────────────────────────────────────────────────────────


def test_status_section_without_a_record_explains_itself():
    section = kbi.status_section(None, "file")
    assert section["available"] is False and "rebuild" in section["note"]


def test_status_section_is_compact_and_shows_staleness(tmp_path):
    repo = make_repo(
        tmp_path / "src" / "app",
        {"project.yaml": "metadata:\n  version: 1.2.3\n"},
        tag="v1.2.3",
    )
    info = kbi.build_info(
        tmp_path / "src", trigger="build", counts={"chunks": 3}, model_name="m"
    )
    commit_file(repo)
    section = kbi.status_section(info, "file")
    assert section["available"] and section["origin"] == "file"
    assert section["stale"] is True and section["sources_not_current"] == 1
    assert section["trigger"] == "build" and section["embedding_model"] == "m"
    (src,) = section["sources"]
    assert (
        src["commit"] == info["sources"][0]["commit"][:12]
    )  # short in the status, full in the file
    assert src["tag"] == "v1.2.3" and src["project_version"] == "1.2.3"
    assert src["state"] == "behind" and src["commits_since"] == 1


def test_status_section_never_raises(monkeypatch, tmp_path):
    make_repo(tmp_path / "src" / "app")
    info = kbi.build_info(tmp_path / "src", trigger="build")
    monkeypatch.setattr(
        kbi, "staleness", lambda _info: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    section = kbi.status_section(info, "memory")
    assert "boom" in section["error"] and section["origin"] == "memory"


# ── the write paths (heavy dependencies; skipped without them) ───────────────


def test_build_knowledge_base_puts_the_record_into_the_dataset(tmp_path, monkeypatch):
    pytest.importorskip("faiss")
    pytest.importorskip("rank_bm25")
    make_source = pytest.importorskip("make_source")

    repo = make_repo(
        tmp_path / "src" / "app",
        {"docs/a.md": "# A\ntext about relays\n"},
        tag="v2.0.0",
    )

    def fake_embeddings(texts, model_name=None):
        rng = np.random.default_rng(0)
        mat = rng.normal(size=(len(texts), 8)).astype("float32")
        return None, mat / np.linalg.norm(mat, axis=1, keepdims=True)

    monkeypatch.setattr(make_source, "create_embeddings", fake_embeddings)
    kb = make_source.build_knowledge_base(
        str(tmp_path / "src"), model_name="test-model"
    )

    assert kbi.CHUNK_ID in kb["chunks"]
    chunk = kb["chunks"][kbi.CHUNK_ID]
    assert (
        chunk["type"] == kbi.CHUNK_TYPE
        and git(repo, "rev-parse", "HEAD") in chunk["text"]
    )
    assert any(
        n["chunk_id"] == kbi.CHUNK_ID for n in kb["nodes"].values()
    ), "the record must become a graph node"
    assert kb["build_info"]["kb"]["embedding_model"] == "test-model"
    assert (
        kb["build_info"]["kb"]["counts"]["chunks"] == len(kb["chunks"]) - 1
    )  # the record itself is not counted
    assert kb["build_info"]["sources"][0]["tag"] == "v2.0.0"


def test_incremental_update_refreshes_record_chunk_and_file(tmp_path):
    pytest.importorskip("watchdog")
    pytest.importorskip("faiss")
    pytest.importorskip("rank_bm25")
    pytest.importorskip("make_source")
    sys.path.insert(
        0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../mcp-server"))
    )
    import pickle

    import kb_watch

    src = tmp_path / "src"
    repo = make_repo(src / "app", {"docs/a.md": "# A\nfirst\n"})
    kb_dir = tmp_path / "kb_data"
    (kb_dir / "pkl").mkdir(parents=True)
    (kb_dir / "pkl" / "chunks.pkl").write_bytes(pickle.dumps({}))
    md = str(repo / "docs" / "a.md")

    kb_watch.incremental_update(src, [md], [], kb_dir, _FakeModel())
    first = kbi.load(kb_dir / "pkl")
    assert first["kb"]["trigger"] == "watch"
    assert first["sources"][0]["commit"] == git(repo, "rev-parse", "HEAD")
    chunks = pickle.loads((kb_dir / "pkl" / "chunks.pkl").read_bytes())
    assert kbi.CHUNK_ID in chunks

    # a source moves on: the next update records the new commit, keeps built_at, and does not add a second record
    first["kb"]["built_at"] = "2026-01-01T00:00:00Z"
    kbi.write(kb_dir / "pkl", first)
    (repo / "docs" / "a.md").write_text("# A\nsecond\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "second")
    kb_watch.incremental_update(src, [md], [], kb_dir, _FakeModel())

    second = kbi.load(kb_dir / "pkl")
    assert (
        second["sources"][0]["commit"]
        == git(repo, "rev-parse", "HEAD")
        != first["sources"][0]["commit"]
    )
    assert second["kb"]["built_at"] == "2026-01-01T00:00:00Z"
    chunks = pickle.loads((kb_dir / "pkl" / "chunks.pkl").read_bytes())
    assert [c for c in chunks if c == kbi.CHUNK_ID] == [kbi.CHUNK_ID]
    assert second["kb"]["counts"]["chunks"] == len(chunks) - 1
    assert kbi.staleness(second)["stale"] is False


def test_the_server_status_section_reads_the_file_next_to_the_pkl_files(tmp_path):
    make_repo(tmp_path / "src" / "app")
    kbi.write(
        tmp_path / "kb_data" / "pkl", kbi.build_info(tmp_path / "src", trigger="build")
    )
    section = kbi.status_section(kbi.load(tmp_path / "kb_data" / "pkl"), "file")
    assert section["available"] and section["stale"] is False


# ── the server: kb_status, the in-memory watch update and the bootstrap ──────


def _server(monkeypatch):
    for dep in ("mcp", "faiss", "rank_bm25", "make_source"):
        pytest.importorskip(dep)
    sys.path.insert(
        0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../mcp-server"))
    )
    import server

    return server


def test_kb_status_has_a_build_section_from_the_file(tmp_path, monkeypatch):
    server = _server(monkeypatch)
    make_repo(tmp_path / "src" / "app", tag="v3.0.0")
    pkl = tmp_path / "kb_data" / "pkl"
    kbi.write(pkl, kbi.build_info(tmp_path / "src", trigger="build"))
    monkeypatch.setattr(server, "DATA_DIR", pkl)
    monkeypatch.setattr(server, "load_kb", lambda: {"chunks": {}, "nodes": {}})

    build = server.kb_status()["build"]
    assert build["available"] and build["origin"] == "file" and build["stale"] is False
    assert (
        build["sources"][0]["tag"] == "v3.0.0"
        and build["sources"][0]["state"] == "current"
    )


def test_kb_status_prefers_the_in_memory_record(tmp_path, monkeypatch):
    server = _server(monkeypatch)
    make_repo(tmp_path / "src" / "app")
    monkeypatch.setattr(
        server, "DATA_DIR", tmp_path / "kb_data" / "pkl"
    )  # no file at all
    memory = kbi.build_info(tmp_path / "src", trigger="watch")
    monkeypatch.setattr(
        server, "load_kb", lambda: {"chunks": {}, "nodes": {}, "build_info": memory}
    )

    build = server.kb_status()["build"]
    assert (
        build["available"]
        and build["origin"] == "memory"
        and build["trigger"] == "watch"
    )


def test_kb_status_without_a_record_says_so(tmp_path, monkeypatch):
    server = _server(monkeypatch)
    monkeypatch.setattr(server, "DATA_DIR", tmp_path / "kb_data" / "pkl")
    monkeypatch.setattr(server, "load_kb", lambda: {"chunks": {}, "nodes": {}})
    build = server.kb_status()["build"]
    assert build["available"] is False and "rebuild" in build["note"]


def test_in_process_watch_update_refreshes_the_record_in_memory_only(
    tmp_path, monkeypatch
):
    server = _server(monkeypatch)
    repo = make_repo(tmp_path / "src" / "app")
    pkl = tmp_path / "kb_data" / "pkl"
    pkl.mkdir(parents=True)
    chunk = {
        "id": "c1", "text": "relay hosts", "file_path": "docs/a.md", "file_paths": ["docs/a.md"],
        "section": "A", "start_line": 1, "end_line": 1, "lang": "en", "type": "section",
        "tags": [], "category": [], "used_in": [], "related_nodes": [], "entrypoint": False,
    }  # fmt: skip
    kb = {
        "chunks": {"c1": chunk}, "nodes": {}, "edges": [], "adj": {}, "chunk_to_nodes": {},
        "embeddings_by_id": {"c1": np.ones(4, dtype="float32")}, "embedding_model": _FakeModel(),
    }  # fmt: skip
    monkeypatch.setattr(server, "_kb", kb)
    monkeypatch.setattr(server, "_watch_dir", tmp_path / "src")
    monkeypatch.setattr(server, "DATA_DIR", pkl)
    monkeypatch.setattr(server, "_watch_process_file", lambda fp: [])

    server._incremental_update_kb([], [])
    first = kb["build_info"]
    assert kbi.CHUNK_ID in kb["chunks"] and kbi.CHUNK_ID in kb["embeddings_by_id"]
    assert first["kb"]["trigger"] == "watch" and first["kb"]["counts"]["chunks"] == 1
    assert first["sources"][0]["commit"] == git(repo, "rev-parse", "HEAD")
    assert not (
        pkl / kbi.FILE_NAME
    ).exists(), (
        "an in-memory update must not claim a file state the pkl files do not have"
    )

    commit_file(repo)
    server._incremental_update_kb([], [])
    assert [c for c in kb["chunks"] if c == kbi.CHUNK_ID] == [kbi.CHUNK_ID]
    assert (
        kb["build_info"]["sources"][0]["commit"]
        == git(repo, "rev-parse", "HEAD")
        != first["sources"][0]["commit"]
    )
    assert kb["build_info"]["kb"]["built_at"] == first["kb"]["built_at"]


def test_bootstrap_writes_the_record_with_the_pkl_files(tmp_path, monkeypatch):
    server = _server(monkeypatch)
    import pickle

    import make_source

    repo = make_repo(tmp_path / "src" / "app", {"docs/a.md": "# A\nrelay text\n"})
    pkl = tmp_path / "kb_data" / "pkl"

    def fake_embeddings(texts, model_name=None):
        rng = np.random.default_rng(1)
        mat = rng.normal(size=(len(texts), 8)).astype("float32")
        return None, mat / np.linalg.norm(mat, axis=1, keepdims=True)

    monkeypatch.setattr(make_source, "create_embeddings", fake_embeddings)
    monkeypatch.setattr(server, "DATA_DIR", pkl)
    server._bootstrap_kb_from_source(tmp_path / "src")

    info = kbi.load(pkl)
    assert info["kb"]["trigger"] == "boot" and info["sources"][0]["commit"] == git(
        repo, "rev-parse", "HEAD"
    )
    chunks = pickle.loads((pkl / "chunks.pkl").read_bytes())
    assert kbi.CHUNK_ID in chunks
    assert info["kb"]["counts"]["chunks"] == len(chunks) - 1
