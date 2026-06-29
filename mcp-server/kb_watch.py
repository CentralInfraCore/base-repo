#!/usr/bin/env python3
"""
kb_watch.py — Incremental KB updater for development use.

Watches any directory for file changes and keeps the knowledge base PKLs
up-to-date without a full rebuild.  Only newly changed files are re-processed;
existing embeddings are reused from the sidecar `embeddings_by_id.pkl`.

Works with any repo or directory — not MCP-specific.

Usage:
    python mcp-server/kb_watch.py <watch_dir> [--kb-dir kb_data] [--interval 2]
    python mcp-server/kb_watch.py <watch_dir> --once    # single scan + exit
"""

import argparse
import hashlib
import json
import os
import pickle
import subprocess
import sys
import time
from pathlib import Path

import numpy as np
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# make_source lives one level up (next to mcp-server/)
sys.path.insert(0, str(Path(__file__).parent.parent))
import make_source  # noqa: E402
from make_source import _generate_chunk_id  # noqa: E402


# ── file-state tracking ─────────────────────────────────────────────────────

_STATE_FILE = '.file_state.json'
_WATCHED_EXTS = ('.md', '.yaml', '.yml', '.go', '.py')

# Generator config: file types that need companion YAML generated
_GENERATORS = {
    '.go': 'go.meta.gen.py',
    '.py': 'py.meta.gen.py',
}

# Directories to exclude from indexing
_EXCLUDE_DIRS = {
    'p_venv', '.venv', 'venv',  # Python virtual environments
    '.git', '.github',           # Git metadata
    'node_modules', '.npm',      # Node.js
    '.mcp_data',                 # Generated KB data
    '__pycache__', '.pytest_cache', '.mypy_cache',  # Python caches
    'dist', 'build', '.egg-info',  # Build artifacts
}


def _file_hash(path: str) -> str:
    try:
        with open(path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return ''


def load_file_state(kb_dir: Path) -> dict:
    p = kb_dir / _STATE_FILE
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            pass
    return {}


def save_file_state(kb_dir: Path, state: dict) -> None:
    (kb_dir / _STATE_FILE).write_text(json.dumps(state, indent=2))


def save_manifest(kb_dir: Path, status: dict) -> None:
    """Write kb_manifest.json with index version info."""
    manifest = {
        "timestamp": time.time(),
        "chunks_mtime": status.get("chunks_mtime", 0),
        "search_mtime": status.get("search_mtime", 0),
        "graph_mtime": status.get("graph_mtime", 0),
        "metadata_mtime": status.get("metadata_mtime", 0),
        "graph_stale": status.get("graph_stale", False),
    }
    (kb_dir / "kb_manifest.json").write_text(json.dumps(manifest, indent=2))


def scan_directory(watch_dir: Path) -> dict:
    """Return {abs_path_str: content_hash} for all processable files."""
    result = {}
    for root, dirs, files in os.walk(watch_dir):
        # In-place modify dirs to skip excluded directories
        dirs[:] = [d for d in dirs if d not in _EXCLUDE_DIRS]

        for fname in files:
            if any(fname.endswith(e) for e in _WATCHED_EXTS) and not fname.startswith('.'):
                p = os.path.join(root, fname)
                result[p] = _file_hash(p)
    return result


def diff_state(watch_dir: Path, old_state: dict) -> tuple[list, list, dict]:
    """Return (changed_or_new, deleted, current_scan)."""
    current = scan_directory(watch_dir)
    changed = [p for p, h in current.items() if old_state.get(p) != h]
    deleted = [p for p in old_state if p not in current]
    return changed, deleted, current


def _generate_yaml_companions(watch_dir: Path, changed_files: list) -> list:
    """Generate or merge YAML companions for .go and .py files using go.meta.gen.py / py.meta.gen.py.

    For new source files: generates YAML skeleton.
    For existing source files with companion YAML: merges updates (preserves human-edited semantic fields).

    Returns list of newly generated/merged .yaml file paths (to be included in processing).
    """
    import subprocess
    generated = []

    # Locate generator scripts (siblings of kb_watch.py)
    generators_dir = Path(__file__).parent.parent / "tools"

    for file_path in changed_files:
        ext = Path(file_path).suffix
        if ext not in _GENERATORS:
            continue

        yaml_path = Path(file_path).with_suffix('.yaml')
        generator_name = _GENERATORS[ext]
        generator_script = generators_dir / generator_name

        if not generator_script.exists():
            continue  # Generator not available, skip

        try:
            # Determine if we should merge (YAML exists) or generate fresh
            if yaml_path.exists():
                # YAML exists: use --merge to update auto-detected fields while preserving semantics
                print(f"  [gen] {generator_name} --merge {Path(file_path).name}", flush=True)
                subprocess.run(
                    [sys.executable, str(generator_script), "--merge", file_path],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.STDOUT,
                    timeout=10,
                    check=False
                )
            else:
                # YAML missing: generate skeleton
                print(f"  [gen] {generator_name} {Path(file_path).name}", flush=True)
                subprocess.run(
                    [sys.executable, str(generator_script), file_path],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.STDOUT,
                    timeout=10,
                    check=False
                )

            if yaml_path.exists():
                generated.append(str(yaml_path))
                mode = "merged" if Path(file_path).with_suffix('.yaml').exists() else "generated"
                print(f"    → {mode} {yaml_path.name}", flush=True)
        except Exception as e:
            print(f"    [warn] generator error: {e}", flush=True)

    return generated


def _resolve_companion_changes(changed: list, deleted: list) -> tuple[list, list]:
    """Resolve Markdown companion YAML changes to MD file changes.

    If foo.yaml changes and foo.md exists, process foo.md instead (avoid duplicate chunks).
    If foo.yaml is deleted and foo.md exists, mark foo.md as changed (to clear stale metadata).
    """
    resolved_changed = []
    resolved_deleted = []

    for fp in changed:
        if fp.endswith(('.yaml', '.yml')):
            base = os.path.splitext(fp)[0]
            md_path = base + '.md'
            if os.path.exists(md_path):
                # YAML has Markdown companion: process the .md instead
                if md_path not in resolved_changed:
                    resolved_changed.append(md_path)
            else:
                # YAML is standalone: process as-is
                resolved_changed.append(fp)
        else:
            resolved_changed.append(fp)

    for fp in deleted:
        if fp.endswith(('.yaml', '.yml')):
            base = os.path.splitext(fp)[0]
            md_path = base + '.md'
            if os.path.exists(md_path):
                # YAML deleted but .md still exists: clear .md metadata
                if md_path not in resolved_changed:
                    resolved_changed.append(md_path)
            else:
                # Both deleted
                resolved_deleted.append(fp)
        else:
            resolved_deleted.append(fp)

    return resolved_changed, resolved_deleted


# ── single-file processor dispatch ─────────────────────────────────────────

def _classify_yaml(file_path: str) -> str:
    """Determine which processor handles this YAML: 'go' | 'py' | 'md' | 'generic'."""
    base = os.path.splitext(file_path)[0]
    # Check for companion Markdown file first (foo.yaml → foo.md)
    if os.path.exists(base + '.md'):
        return 'md'
    if os.path.exists(base + '.go'):
        return 'go'
    if os.path.exists(base + '.py'):
        return 'py'
    if make_source._is_go_meta_yaml(file_path):
        return 'go'
    if make_source._is_py_meta_yaml(file_path):
        return 'py'
    return 'generic'


def process_file(file_path: str) -> list:
    """Route a single file to the correct make_source processor."""
    if file_path.endswith('.md'):
        return make_source.process_md_file(file_path)
    if file_path.endswith(('.yaml', '.yml')):
        kind = _classify_yaml(file_path)
        if kind == 'go':
            return make_source.process_go_yaml(file_path)
        if kind == 'py':
            return make_source.process_py_yaml(file_path)
        if kind == 'md':
            return []  # companion YAML — content included via .md handler
        return make_source.process_yaml_file(file_path)
    return []


# ── PKL helpers ──────────────────────────────────────────────────────────────

def _pkl_path(kb_dir: Path, name: str) -> Path:
    return kb_dir / 'pkl' / name


def _load_pkl(kb_dir: Path, name: str, default):
    p = _pkl_path(kb_dir, name)
    if p.exists():
        with p.open('rb') as f:
            return pickle.load(f)
    return default


def _dump_pkl(kb_dir: Path, name: str, obj) -> None:
    """Atomically write PKL file using temp + rename."""
    import tempfile
    target = _pkl_path(kb_dir, name)
    temp_fd, temp_path = tempfile.mkstemp(dir=target.parent, prefix='.tmp_', suffix='.pkl')
    try:
        with os.fdopen(temp_fd, 'wb') as f:
            f.write(pickle.dumps(obj))
        os.replace(temp_path, str(target))
    except Exception:
        os.unlink(temp_path)
        raise


def _load_chunks(kb_dir: Path) -> dict:
    """Load chunks.pkl and normalize to dict[chunk_id, chunk_dict]."""
    raw = _load_pkl(kb_dir, 'chunks.pkl', {})
    if isinstance(raw, list):
        return {c['id']: c for c in raw if isinstance(c, dict) and 'id' in c}
    return dict(raw) if isinstance(raw, dict) else {}


# ── incremental update ────────────────────────────────────────────────────

def _chunks_for_files(chunks_by_id: dict, file_paths: list) -> set:
    fp_set = set(file_paths)
    return {
        cid for cid, c in chunks_by_id.items()
        if fp_set & set(c.get('file_paths', [c.get('file_path', '')]))
    }


def _next_chunk_id(chunks_by_id: dict) -> int:
    nums = [int(cid[1:]) for cid in chunks_by_id if cid.startswith('c') and cid[1:].isdigit()]
    return max(nums, default=0) + 1


def incremental_update(watch_dir: Path, changed: list, deleted: list,
                       kb_dir: Path, model) -> dict:
    """
    Process changed/deleted files and update KB PKLs in-place.

    Returns a summary dict: {removed, added, total}.
    """
    # ── load ──────────────────────────────────────────────────────────────
    chunks_by_id: dict = _load_chunks(kb_dir)
    embeddings_by_id: dict = _load_pkl(kb_dir, 'embeddings_by_id.pkl', {})

    # ── remove stale chunks (changed files will be re-added below) ────────
    stale_ids = _chunks_for_files(chunks_by_id, changed + deleted)
    for cid in stale_ids:
        chunks_by_id.pop(cid, None)
        embeddings_by_id.pop(cid, None)

    # ── reprocess changed files ───────────────────────────────────────────
    new_chunks: list = []
    for fp in changed:
        try:
            fc = process_file(fp)
            new_chunks.extend(fc)
        except Exception as exc:
            print(f"  [warn] {os.path.basename(fp)}: {exc}")

    # assign persistent IDs (file_path + type + section based hash)
    for chunk in new_chunks:
        chunk['id'] = _generate_chunk_id(
            chunk['file_path'],
            chunk['type'],
            chunk.get('section', ''),
            chunk.get('text', '')
        )
        chunk.setdefault('file_paths', [chunk.get('file_path', '')])

    # ── embed only new chunks ─────────────────────────────────────────────
    if new_chunks:
        texts = [c.get('text', '') for c in new_chunks]
        vecs = model.encode(texts, normalize_embeddings=True, batch_size=32, show_progress_bar=False)
        for chunk, vec in zip(new_chunks, vecs):
            chunks_by_id[chunk['id']] = chunk
            embeddings_by_id[chunk['id']] = vec.astype('float32')

    # ── rebuild FAISS from ALL current embeddings (no re-encoding) ────────
    try:
        import faiss as _faiss
        import tempfile
        if embeddings_by_id:
            id_order = list(embeddings_by_id.keys())
            mat = np.stack([embeddings_by_id[cid] for cid in id_order]).astype('float32')
            faiss_idx = _faiss.IndexFlatIP(mat.shape[1])
            faiss_idx.add(mat)
            # Atomic write: temp file + rename
            target = _pkl_path(kb_dir, 'faiss.index')
            temp_fd, temp_path = tempfile.mkstemp(dir=target.parent, prefix='.tmp_', suffix='.index')
            try:
                os.close(temp_fd)  # Close fd; FAISS will open it
                _faiss.write_index(faiss_idx, temp_path)
                os.replace(temp_path, str(target))
            except Exception:
                os.unlink(temp_path)
                raise
    except ImportError:
        pass

    # ── rebuild BM25 + inverted index from ALL current chunks ─────────────
    # BM25 is fast (tokenization only, no encoding) — gives correct IDF scores
    all_chunks = list(chunks_by_id.values())
    if all_chunks:
        bm25 = make_source.build_bm25_index(all_chunks)
        inv_index = make_source.create_bm25_inverted_index(all_chunks, bm25)
        _dump_pkl(kb_dir, 'bm25.pkl', bm25)
        _dump_pkl(kb_dir, 'chunk_ids.pkl', [c['id'] for c in all_chunks])
    else:
        inv_index = {}

    # ── rebuild metadata index from ALL current chunks ───────────────────
    if all_chunks:
        metadata_index = make_source.build_metadata_index(all_chunks)
    else:
        metadata_index = {}

    # ── persist ────────────────────────────────────────────────────────────
    _dump_pkl(kb_dir, 'chunks.pkl', chunks_by_id)
    _dump_pkl(kb_dir, 'metadata_index.pkl', metadata_index)
    _dump_pkl(kb_dir, 'embeddings_by_id.pkl', embeddings_by_id)
    _dump_pkl(kb_dir, 'inverted_index.pkl', inv_index)

    return {
        'removed': len(stale_ids),
        'added': len(new_chunks),
        'total': len(chunks_by_id),
        'chunks_mtime': time.time(),
        'search_mtime': time.time(),
        'metadata_mtime': time.time(),
        'graph_stale': True,  # graph not refreshed by watcher
    }


# ── main ─────────────────────────────────────────────────────────────────────

def _load_model(kb_dir: Path):
    from sentence_transformers import SentenceTransformer
    model_name = _load_pkl(kb_dir, 'model_name.pkl', make_source.EMBEDDING_MODEL)
    print(f"Loading model: {model_name}")
    return SentenceTransformer(model_name)


class KBWatchHandler(FileSystemEventHandler):
    """inotify event handler for KB updates."""

    def __init__(self, watch_dir: Path, kb_dir: Path, model, file_state: dict):
        self.watch_dir = watch_dir
        self.kb_dir = kb_dir
        self.model = model
        self.file_state = file_state
        self.pending_files = set()

    def on_modified(self, event):
        if not event.is_directory and self._should_process(event.src_path):
            self.pending_files.add(event.src_path)
            self._process_changes()

    def on_created(self, event):
        if not event.is_directory and self._should_process(event.src_path):
            self.pending_files.add(event.src_path)
            self._process_changes()

    def on_deleted(self, event):
        if not event.is_directory and self._should_process(event.src_path):
            self.pending_files.add(event.src_path)
            self._process_changes()

    def _should_process(self, file_path: str) -> bool:
        """Check if file should be processed."""
        # Check extension and not a hidden file
        if not (any(file_path.endswith(e) for e in _WATCHED_EXTS) and not os.path.basename(file_path).startswith('.')):
            return False
        # Check if it's in an excluded directory
        for excluded in _EXCLUDE_DIRS:
            if f'/{excluded}/' in file_path or f'\\{excluded}\\' in file_path:
                return False
        return True

    def _process_changes(self):
        """Detect and process file changes."""
        changed, deleted, current = diff_state(self.watch_dir, self.file_state)

        # Generator pass: create missing YAML companions for .go and .py files
        generated = _generate_yaml_companions(self.watch_dir, changed)
        if generated:
            changed.extend(generated)
            # Update file_state to reflect newly generated files
            for gen_file in generated:
                current[gen_file] = _file_hash(gen_file)

        # Resolve Markdown companion YAML changes: if foo.yaml changes, process foo.md instead
        changed, deleted = _resolve_companion_changes(changed, deleted)

        if changed or deleted:
            ts = time.strftime('%H:%M:%S')
            print(f"\n[{ts}] {len(changed)} changed, {len(deleted)} deleted")
            for fp in changed:
                print(f"  ~ {os.path.relpath(fp, self.watch_dir)}")
            for fp in deleted:
                print(f"  - {os.path.relpath(fp, self.watch_dir)}")
            try:
                s = incremental_update(self.watch_dir, changed, deleted, self.kb_dir, self.model)
                self.file_state = current  # Replace state entirely (remove deleted files)
                save_file_state(self.kb_dir, self.file_state)
                save_manifest(self.kb_dir, s)
                print(f"  → removed={s['removed']} added={s['added']} total={s['total']} (graph_stale={s['graph_stale']})")
            except Exception as e:
                print(f"  [error] {e}")
        self.pending_files.clear()


def main():
    ap = argparse.ArgumentParser(
        description='Incremental KB watcher — watches any directory, updates KB PKLs on file change (inotify-based)',
    )
    ap.add_argument(
        '--source',
        default=os.environ.get('SOURCE_DIR', './source'),
        help='Source directory to watch (default: env SOURCE_DIR or ./source)'
    )
    ap.add_argument(
        '--kb-dir',
        default=os.environ.get('KB_DATA_DIR', './kb_data'),
        help='KB output directory (default: env KB_DATA_DIR or ./kb_data)'
    )
    ap.add_argument('--once', action='store_true', help='Single scan then exit')
    args = ap.parse_args()

    watch_dir = Path(args.source).resolve()
    kb_dir = Path(args.kb_dir).resolve()
    pkl_dir = kb_dir / 'pkl'
    pkl_dir.mkdir(parents=True, exist_ok=True)

    # Wait for chunks.pkl if KB is being bootstrapped
    chunks_pkl = pkl_dir / 'chunks.pkl'
    if not chunks_pkl.exists():
        print(f"[watch] waiting for KB bootstrap (chunks.pkl not yet created)...", flush=True)
        for i in range(600):  # wait up to 10 minutes
            if chunks_pkl.exists():
                print(f"[watch] KB bootstrap complete, starting watch...", flush=True)
                break
            time.sleep(1)
        else:
            print(f"[watch] timeout waiting for KB bootstrap", file=sys.stderr)
            return

    model = _load_model(kb_dir)
    file_state = load_file_state(kb_dir)

    if args.once:
        changed, deleted, current = diff_state(watch_dir, file_state)
        if changed or deleted:
            s = incremental_update(watch_dir, changed, deleted, kb_dir, model)
            save_file_state(kb_dir, current)
            print(f"removed={s['removed']} added={s['added']} total={s['total']}")
        else:
            print("No changes.")
        return

    print(f"Watching {watch_dir}")
    print(f"KB:       {kb_dir}")
    print("Press Ctrl-C to stop\n")

    event_handler = KBWatchHandler(watch_dir, kb_dir, model, file_state)
    observer = Observer()
    observer.schedule(event_handler, str(watch_dir), recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        observer.join()
        print("\nStopped.")


if __name__ == '__main__':
    main()
