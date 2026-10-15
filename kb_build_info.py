"""kb_build_info.py — provenance of a knowledge-base build.

A KB is built from a tree of source repositories (usually git submodules under
``source/``). Nothing in the pkl files says *which commit* of which repository
the chunks came from, so "how stale is the KB?" could only be answered by
reading git logs by hand.

This module records that, in the style of ``project.yaml``:

* ``build_info.yaml`` next to the pkl files, per source repository: remote,
  commit, tag-based ``describe``, branch, whether the checked-out tree was dirty
  and the ``metadata.version`` of its ``project.yaml``;
* one meta chunk (``c_kb_build_info``) in the dataset with the same content, so
  ``search_nodes`` finds it without file access;
* :func:`staleness`, which compares the recorded commits with the source trees as
  they are now — the ``build`` section of ``kb_status`` is built from it.

It is written by every path that changes the KB (``make_source.py``,
``kb_watch.py``, the server's bootstrap), so it cannot drift from the data.
Only the standard library and PyYAML are used.
"""

from __future__ import annotations

import os
import re
import subprocess  # nosec B404 - runs git with argv lists, no shell
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

SCHEMA = "kb-build-info/v1"
FILE_NAME = "build_info.yaml"
CHUNK_ID = "c_kb_build_info"
CHUNK_TYPE = "kb_build_info"
CHUNK_PATH = "kb_data/build_info.yaml"  # virtual: the file lives next to the pkl files
CHUNK_TAGS = ["kb-meta", "build-info", "provenance"]

_GIT_TIMEOUT = 15
_MAX_DEPTH = 8
_SKIP_DIRS = {
    "p_venv", ".venv", "venv", "node_modules", ".npm", "__pycache__",
    ".pytest_cache", ".mypy_cache", "dist", "build", "target", ".mcp_data",
}  # fmt: skip


def _now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _git(repo: Path, *args: str) -> str | None:
    """Run ``git -C repo args``; the stripped stdout, or None on any failure."""
    try:
        res = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            timeout=_GIT_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if res.returncode != 0:
        return None
    return res.stdout.strip()


def _strip_credentials(url: str | None) -> str | None:
    """Drop ``user:password@`` from a URL so a token never lands in the KB."""
    if not url:
        return None
    return re.sub(r"^([a-zA-Z][a-zA-Z0-9+.-]*://)[^/@]+@", r"\1", url)


def _project_version(repo: Path) -> str | None:
    path = repo / "project.yaml"
    if not path.is_file():
        return None
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return None
    meta = data.get("metadata") if isinstance(data, dict) else None
    version = meta.get("version") if isinstance(meta, dict) else None
    return str(version) if version is not None else None


def _submodule_paths(repo: Path) -> list[Path]:
    """Paths declared in ``repo/.gitmodules`` (nested submodules)."""
    gm = repo / ".gitmodules"
    if not gm.is_file():
        return []
    paths: list[Path] = []
    try:
        for line in gm.read_text(encoding="utf-8").splitlines():
            m = re.match(r"\s*path\s*=\s*(.+?)\s*$", line)
            if m:
                paths.append(repo / m.group(1))
    except OSError:
        return []
    return paths


def _describe_repo(repo: Path, rel: str) -> dict[str, Any]:
    commit = _git(repo, "rev-parse", "HEAD")
    status = _git(repo, "status", "--porcelain", "--untracked-files=no")
    row: dict[str, Any] = {
        "path": rel,
        "abs_path": str(repo),
        "remote": _strip_credentials(
            _git(repo, "config", "--get", "remote.origin.url")
        ),
        "commit": commit,
        "commit_date": _git(repo, "log", "-1", "--format=%cI") if commit else None,
        "branch": _git(repo, "symbolic-ref", "--short", "-q", "HEAD"),
        "describe": _git(repo, "describe", "--tags", "--always") if commit else None,
        "tag": _git(repo, "describe", "--tags", "--exact-match") if commit else None,
        "dirty": bool(status),
        "dirty_files": len(status.splitlines()) if status else 0,
        "project_version": _project_version(repo),
    }
    if commit is None:
        row["error"] = "git could not read HEAD"
    return row


def collect_sources(source_dir: str | Path) -> list[dict[str, Any]]:
    """Describe every git repository under ``source_dir``, sorted by path.

    A repository is a directory with a ``.git`` entry (a file for submodules). The
    walk does not descend into a repository except through the paths its
    ``.gitmodules`` declares, so large work trees are never scanned. If no
    repository is found but ``source_dir`` lies inside one, that repository is
    reported with ``path: "."``.
    """
    root = Path(source_dir).resolve()
    found: dict[Path, dict[str, Any]] = {}

    def visit(repo: Path) -> None:
        rel = os.path.relpath(repo, root).replace(os.sep, "/")
        found[repo] = _describe_repo(repo, rel)
        for sub in _submodule_paths(repo):
            if sub.is_dir() and (sub / ".git").exists() and sub not in found:
                visit(sub)

    if root.is_dir():
        for dirpath, dirnames, _ in os.walk(root):
            here = Path(dirpath)
            depth = len(here.relative_to(root).parts)
            if (here / ".git").exists():
                if here not in found:
                    visit(here)
                dirnames[:] = []  # nested repos are reached through .gitmodules
                continue
            dirnames[:] = sorted(
                d
                for d in dirnames
                if d not in _SKIP_DIRS and not d.startswith(".") and depth < _MAX_DEPTH
            )

        if not found:
            top = _git(root, "rev-parse", "--show-toplevel")
            if top:
                row = _describe_repo(Path(top), ".")
                row["abs_path"] = top
                found[Path(top)] = row

    return sorted(found.values(), key=lambda r: r["path"])


def _builder_info() -> dict[str, Any]:
    here = Path(__file__).resolve().parent
    commit = _git(here, "rev-parse", "HEAD")
    status = _git(here, "status", "--porcelain", "--untracked-files=no")
    return {
        "commit": commit,
        "describe": _git(here, "describe", "--tags", "--always") if commit else None,
        "dirty": bool(status),
    }


def build_info(
    source_dir: str | Path,
    trigger: str,
    counts: dict[str, int] | None = None,
    model_name: str | None = None,
    previous: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """The record for the KB as it is now.

    ``trigger`` is ``build`` (a full build: ``built_at`` is now), or ``watch`` /
    ``boot`` (an update: ``built_at`` is carried over from ``previous`` when there
    is one).
    """
    now = _now()
    prev_kb = (previous or {}).get("kb") or {}
    built_at = now if trigger == "build" else prev_kb.get("built_at", now)
    sources = collect_sources(source_dir)
    return {
        "schema": SCHEMA,
        "kb": {
            "built_at": built_at,
            "updated_at": now,
            "trigger": trigger,
            "embedding_model": model_name or prev_kb.get("embedding_model"),
            "counts": {**(counts or {}), "sources": len(sources)},
        },
        "builder": _builder_info(),
        "source_root": str(Path(source_dir).resolve()),
        "sources": sources,
    }


def render_text(info: dict[str, Any]) -> str:
    """The YAML text of the record (also the text of the meta chunk)."""
    header = (
        "# Knowledge-base build info: which commit / tag of each source repository this\n"
        "# KB (chunks, graph, indexes) was built from. Written automatically with every\n"
        "# KB build and update.\n"
    )
    return header + yaml.safe_dump(
        info, sort_keys=False, allow_unicode=True, default_flow_style=False
    )


def write(pkl_dir: str | Path, info: dict[str, Any]) -> Path:
    """Atomically write ``build_info.yaml`` into ``pkl_dir``."""
    target = Path(pkl_dir) / FILE_NAME
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=".tmp_", suffix=".yaml")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(render_text(info))
        os.replace(tmp, target)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    return target


def load(pkl_dir: str | Path) -> dict[str, Any] | None:
    """The recorded info next to the pkl files, or None if absent / unreadable."""
    path = Path(pkl_dir) / FILE_NAME
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return None
    return data if isinstance(data, dict) and data.get("schema") == SCHEMA else None


def meta_chunk(info: dict[str, Any]) -> dict[str, Any]:
    """The dataset chunk carrying ``info`` (fixed id, so it is replaced, not added)."""
    text = render_text(info)
    return {
        "id": CHUNK_ID,
        "text": text,
        "file_path": CHUNK_PATH,
        "file_paths": [CHUNK_PATH],
        "section": "build_info",
        "start_line": 1,
        "end_line": len(text.splitlines()),
        "lang": "yaml",
        "type": CHUNK_TYPE,
        "tags": list(CHUNK_TAGS),
        "category": ["kb"],
        "used_in": [],
        "related_nodes": [],
        "entrypoint": False,
        "description": "Build provenance of this knowledge base: source repository commits and tags.",
    }


def upsert_meta_chunk(
    chunks: dict[str, Any],
    embeddings: dict[str, Any] | None,
    info: dict[str, Any],
    model: Any,
) -> dict[str, Any]:
    """Replace the meta chunk in ``chunks`` (and its embedding, if a model is given)."""
    chunk = meta_chunk(info)
    chunks[CHUNK_ID] = chunk
    if embeddings is not None and model is not None:
        vec = model.encode(
            [chunk["text"]], normalize_embeddings=True, show_progress_bar=False
        )[0]
        embeddings[CHUNK_ID] = vec.astype("float32")
    return chunk


def _rev_count(repo: Path, spec: str) -> int | None:
    out = _git(repo, "rev-list", "--count", spec)
    return int(out) if out is not None and out.isdigit() else None


def _upstream(repo: Path, current: str | None) -> dict[str, Any]:
    """How far the checked-out commit is behind its upstream, from local refs only.

    Only as fresh as the last ``git fetch`` of that repository, so the time of the
    last fetch is reported with it: ``behind_upstream: 0`` next to an old (or
    missing) ``upstream_fetched_at`` means "not known to be behind", not "up to date".
    """
    ref = _git(
        repo, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}"
    ) or _git(repo, "symbolic-ref", "-q", "--short", "refs/remotes/origin/HEAD")
    fetched_at = None
    fetch_head = _git(repo, "rev-parse", "--git-path", "FETCH_HEAD")
    if fetch_head:
        path = Path(fetch_head) if os.path.isabs(fetch_head) else repo / fetch_head
        if path.is_file():
            stamp = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
            fetched_at = stamp.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    behind = _rev_count(repo, f"{current}..{ref}") if ref and current else None
    return {
        "upstream_ref": ref,
        "behind_upstream": behind,
        "upstream_fetched_at": fetched_at,
    }


def staleness(info: dict[str, Any]) -> dict[str, Any]:
    """Compare each recorded source with its working tree as it is now.

    Per source ``state`` is one of ``current``, ``behind`` (the tree has
    ``commits_since`` newer commits), ``ahead`` (the tree is on an older commit
    than recorded), ``diverged``, ``unknown`` (the recorded commit is not in the
    repository any more) or ``missing`` (the path is gone). ``dirty_now`` reports
    uncommitted changes to tracked files. ``behind_upstream`` is how far the working
    tree itself is behind its upstream (see :func:`_upstream`); it does not affect
    ``stale``, which is about the KB versus the working trees.
    """
    rows: list[dict[str, Any]] = []
    for src in info.get("sources") or []:
        repo = Path(src.get("abs_path") or "")
        recorded = src.get("commit")
        row: dict[str, Any] = {"path": src.get("path"), "recorded_commit": recorded}
        if not repo.is_dir():
            row.update(
                state="missing",
                current_commit=None,
                commits_since=None,
                dirty_now=None,
                upstream_ref=None,
                behind_upstream=None,
                upstream_fetched_at=None,
            )
            rows.append(row)
            continue
        current = _git(repo, "rev-parse", "HEAD")
        status = _git(repo, "status", "--porcelain", "--untracked-files=no")
        row["current_commit"] = current
        row["dirty_now"] = bool(status)
        row.update(_upstream(repo, current))
        if current is None or recorded is None:
            row.update(state="unknown", commits_since=None)
        elif current == recorded:
            row.update(state="current", commits_since=0)
        elif _git(repo, "cat-file", "-e", f"{recorded}^{{commit}}") is None:
            row.update(
                state="unknown", commits_since=None
            )  # recorded commit is gone (rewritten history, shallow clone)
        else:
            newer = _rev_count(repo, f"{recorded}..{current}")
            older = _rev_count(repo, f"{current}..{recorded}")
            if older == 0:
                row.update(state="behind", commits_since=newer)
            elif newer == 0:
                row.update(state="ahead", commits_since=-(older or 0))
            else:
                row.update(state="diverged", commits_since=newer)
        rows.append(row)
    stale = [r for r in rows if r["state"] != "current"]
    return {
        "checked_at": _now(),
        "stale": bool(stale),
        "sources_not_current": len(stale),
        "sources_dirty_now": sum(1 for r in rows if r.get("dirty_now")),
        "sources_behind_upstream": sum(
            1 for r in rows if (r.get("behind_upstream") or 0) > 0
        ),
        "sources": rows,
    }


def status_section(info: dict[str, Any] | None, origin: str) -> dict[str, Any]:
    """The ``build`` section of ``kb_status``; never raises."""
    if info is None:
        return {
            "available": False,
            "note": f"no {FILE_NAME} next to the pkl files: this KB was built before build info existed; rebuild it to record the source versions",
        }
    try:
        fresh = staleness(info)
        by_path = {r["path"]: r for r in fresh["sources"]}
        sources = []
        for src in info.get("sources") or []:
            cur = by_path.get(src.get("path"), {})
            sources.append(
                {
                    "path": src.get("path"),
                    "commit": (src.get("commit") or "")[:12] or None,
                    "describe": src.get("describe"),
                    "tag": src.get("tag"),
                    "branch": src.get("branch"),
                    "dirty_at_build": src.get("dirty"),
                    "project_version": src.get("project_version"),
                    "state": cur.get("state"),
                    "commits_since": cur.get("commits_since"),
                    "dirty_now": cur.get("dirty_now"),
                    "behind_upstream": cur.get("behind_upstream"),
                    "upstream_fetched_at": cur.get("upstream_fetched_at"),
                }
            )
        return {
            "available": True,
            "origin": origin,
            **(info.get("kb") or {}),
            "builder": info.get("builder"),
            "stale": fresh["stale"],
            "sources_not_current": fresh["sources_not_current"],
            "sources_dirty_now": fresh["sources_dirty_now"],
            "sources_behind_upstream": fresh["sources_behind_upstream"],
            "checked_at": fresh["checked_at"],
            "sources": sources,
        }
    except (
        Exception
    ) as exc:  # noqa: BLE001 - status must never fail because of provenance
        return {
            "available": True,
            "origin": origin,
            "error": f"could not evaluate staleness: {exc}",
        }
