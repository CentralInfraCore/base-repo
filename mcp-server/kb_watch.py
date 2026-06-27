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
import sys
import time
from pathlib import Path

import numpy as np

# make_source lives one level up (next to mcp-server/)
sys.path.insert(0, str(Path(__file__).parent.parent))
import make_source  # noqa: E402


# ── file-state tracking ─────────────────────────────────────────────────────

_STATE_FILE = '.file_state.json'
_WATCHED_EXTS = ('.md', '.yaml', '.yml')


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


def scan_directory(watch_dir: Path) -> dict:
    """Return {abs_path_str: content_hash} for all processable files."""
    result = {}
    for root, _, files in os.walk(watch_dir):
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


# ── single-file processor dispatch ─────────────────────────────────────────

def _classify_yaml(file_path: str) -> str:
    """Determine which processor handles this YAML: 'go' | 'py' | 'md' | 'generic'."""
    base = os.path.splitext(file_path)[0]
    if os.path.exists(base + '.go'):
        return 'go'
    if os.path.exists(base + '.py'):
        return 'py'
    if os.path.exists(base + '.md'):
        return 'md'
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
    _pkl_path(kb_dir, name).write_bytes(pickle.dumps(obj))


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

    # assign IDs continuing from current max
    next_id = _next_chunk_id(chunks_by_id)
    for i, chunk in enumerate(new_chunks):
        chunk['id'] = f'c{next_id + i}'
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
        if embeddings_by_id:
            id_order = list(embeddings_by_id.keys())
            mat = np.stack([embeddings_by_id[cid] for cid in id_order]).astype('float32')
            faiss_idx = _faiss.IndexFlatIP(mat.shape[1])
            faiss_idx.add(mat)
            _faiss.write_index(faiss_idx, str(_pkl_path(kb_dir, 'faiss.index')))
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

    # ── persist ────────────────────────────────────────────────────────────
    _dump_pkl(kb_dir, 'chunks.pkl', chunks_by_id)
    _dump_pkl(kb_dir, 'embeddings_by_id.pkl', embeddings_by_id)
    _dump_pkl(kb_dir, 'inverted_index.pkl', inv_index)

    return {'removed': len(stale_ids), 'added': len(new_chunks), 'total': len(chunks_by_id)}


# ── main ─────────────────────────────────────────────────────────────────────

def _load_model(kb_dir: Path):
    from sentence_transformers import SentenceTransformer
    model_name = _load_pkl(kb_dir, 'model_name.pkl', make_source.EMBEDDING_MODEL)
    print(f"Loading model: {model_name}")
    return SentenceTransformer(model_name)


def main():
    ap = argparse.ArgumentParser(
        description='Incremental KB watcher — watches any directory, updates KB PKLs on file change',
    )
    ap.add_argument('watch_dir', help='Directory to watch')
    ap.add_argument('--kb-dir', default='kb_data', help='KB output directory (default: kb_data)')
    ap.add_argument('--interval', type=float, default=2.0, help='Poll interval in seconds (default: 2)')
    ap.add_argument('--once', action='store_true', help='Single scan then exit')
    args = ap.parse_args()

    watch_dir = Path(args.watch_dir).resolve()
    kb_dir = Path(args.kb_dir).resolve()
    (kb_dir / 'pkl').mkdir(parents=True, exist_ok=True)

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
    print(f"KB:       {kb_dir}  (interval: {args.interval}s — Ctrl-C to stop)")
    try:
        while True:
            changed, deleted, current = diff_state(watch_dir, file_state)
            if changed or deleted:
                ts = time.strftime('%H:%M:%S')
                print(f"\n[{ts}] {len(changed)} changed, {len(deleted)} deleted")
                for fp in changed:
                    print(f"  ~ {os.path.relpath(fp, watch_dir)}")
                for fp in deleted:
                    print(f"  - {os.path.relpath(fp, watch_dir)}")
                s = incremental_update(watch_dir, changed, deleted, kb_dir, model)
                file_state = current
                save_file_state(kb_dir, file_state)
                print(f"  → removed={s['removed']} added={s['added']} total={s['total']}")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == '__main__':
    main()
