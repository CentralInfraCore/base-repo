import os
import yaml
import markdown
import json
import datetime
import pickle
import sqlite3
import re
import numpy as np
from bs4 import BeautifulSoup
from langdetect import detect, LangDetectException
from sentence_transformers import SentenceTransformer
from rank_bm25 import BM25Okapi
import faiss

EMBEDDING_MODEL = os.environ.get("EMBEDDING_MODEL", "paraphrase-multilingual-MiniLM-L12-v2")

def detect_language(text):
    try:
        return detect(text)
    except LangDetectException:
        return 'unknown'

def load_companion_yaml(md_path):
    """Load a companion .yaml file for an .md file if it exists."""
    yaml_path = os.path.splitext(md_path)[0] + '.yaml'
    if not os.path.exists(yaml_path):
        return None
    try:
        with open(yaml_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        return data if isinstance(data, dict) else None
    except (yaml.YAMLError, IOError):
        return None

def _normalize_list(val):
    """Normalize a YAML value to a list of strings."""
    if not val:
        return []
    if isinstance(val, list):
        return [str(x) for x in val]
    return [str(val)]

def process_md_file(file_path):
    chunks = []
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    companion = load_companion_yaml(file_path)
    meta = {}
    if companion:
        meta = {
            'tags':          _normalize_list(companion.get('tags')),
            'category':      _normalize_list(companion.get('category')),
            'used_in':       _normalize_list(companion.get('used_in')),
            'related_nodes': _normalize_list(companion.get('related_nodes')),
            'entrypoint':    bool(companion.get('entrypoint', False)),
            'description':   str(companion.get('description', '')).strip(),
        }

    current_chunk_lines, current_header, start_line = [], "", 1
    for i, line in enumerate(lines):
        match = re.match(r'^(#+)\s(.*)', line)
        if match:
            if current_chunk_lines:
                text = "".join(current_chunk_lines).strip()
                if text:
                    chunk = {'text': text, 'file_path': file_path, 'section': current_header,
                             'start_line': start_line, 'end_line': i,
                             'lang': detect_language(text), 'type': 'section'}
                    chunk.update(meta)
                    chunks.append(chunk)
            start_line = i + 1
            current_header = match.group(2).strip()
            current_chunk_lines = [line]
        else:
            current_chunk_lines.append(line)

    if current_chunk_lines:
        text = "".join(current_chunk_lines).strip()
        if text:
            chunk = {'text': text, 'file_path': file_path, 'section': current_header,
                     'start_line': start_line, 'end_line': len(lines),
                     'lang': detect_language(text), 'type': 'section'}
            chunk.update(meta)
            chunks.append(chunk)
    return chunks

def process_go_yaml(file_path):
    """Process a .go.yaml companion file as structured knowledge chunks.

    The .go source file is not indexed (code excluded by design); this YAML
    is the sole knowledge source for Go files in the KB.

    Produces one chunk per object defined in the file.
    File-level metadata (tags, category, used_in) is applied to all chunks.
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            return []
    except (yaml.YAMLError, IOError):
        return []

    meta = {
        'tags':          _normalize_list(data.get('tags')),
        'category':      _normalize_list(data.get('category')),
        'used_in':       _normalize_list(data.get('used_in')),
        'related_nodes': _normalize_list(data.get('related_nodes')),
        'entrypoint':    bool(data.get('entrypoint', False)),
        'description':   str(data.get('description', '')).strip(),
    }

    package = data.get('package', '') or os.path.basename(file_path)
    objects = data.get('objects', [])

    if not objects:
        text = f"package {package}"
        if meta['description']:
            text += f"\n{meta['description']}"
        return [{
            'text': text, 'file_path': file_path,
            'section': package, 'start_line': 1, 'end_line': 1,
            'lang': 'go', 'type': 'go_package', **meta,
        }]

    chunks = []
    for i, obj in enumerate(objects):
        name     = obj.get('name', '')
        kind     = obj.get('kind', '')
        receiver = obj.get('receiver', '')
        desc     = str(obj.get('description', '')).strip()
        refs     = obj.get('references', [])
        impl     = obj.get('implements', [])

        # Build searchable text: signature + description + references
        sig = f"method ({receiver}) {name}" if receiver else f"{kind} {name}"
        lines = [sig]
        if desc:
            lines.append(desc)
        if refs:
            lines.append(f"references: {', '.join(refs)}")
        if impl:
            lines.append(f"implements: {', '.join(impl)}")

        chunk = {
            'text': '\n'.join(lines),
            'file_path': file_path,
            'section': name,
            'start_line': i + 1,
            'end_line': i + 1,
            'lang': 'go',
            'type': f'go_{kind}' if kind else 'go_object',
        }
        chunk.update(meta)
        chunks.append(chunk)

    return chunks


def process_yaml_file(file_path):
    """Processes a YAML file as a single, large chunk to preserve context."""
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            yaml_content = yaml.safe_load(file)
            if not yaml_content:
                return []
            text_content = yaml.dump(yaml_content, allow_unicode=True, default_flow_style=False, indent=2)
            return [{
                'text': text_content,
                'file_path': file_path,
                'section': os.path.basename(file_path),
                'start_line': 1,
                'end_line': len(text_content.splitlines()),
                'lang': 'yaml',
                'type': 'yaml_file',
                'tags': [], 'category': [], 'used_in': [],
                'related_nodes': [], 'entrypoint': False, 'description': '',
            }]
    except (yaml.YAMLError, IOError):
        return []

def create_embeddings(texts, model_name=EMBEDDING_MODEL):
    """Encode texts using a multilingual sentence transformer model."""
    print(f"Loading embedding model: {model_name}")
    model = SentenceTransformer(model_name)
    embeddings = model.encode(texts, show_progress_bar=True, normalize_embeddings=True, batch_size=64)
    return model, np.array(embeddings, dtype='float32')

def build_faiss_index(embeddings):
    """Build FAISS inner-product index (cosine sim with normalized vectors)."""
    dim = embeddings.shape[1]
    index = faiss.IndexFlatIP(dim)
    index.add(embeddings)
    return index

def build_bm25_index(chunks):
    """Build BM25 index for lexical search."""
    tokenized = [chunk['text'].lower().split() or [""] for chunk in chunks]
    return BM25Okapi(tokenized)

def create_bm25_inverted_index(chunks, bm25):
    """Lightweight inverted index from BM25 scores (for SQLite compat)."""
    inverted_index = {}
    for i, chunk in enumerate(chunks):
        tokens = set(chunk['text'].lower().split())
        for word in tokens:
            score = float(bm25.get_scores([word])[i])
            if score > 0.01:
                inverted_index.setdefault(word, []).append({'chunk_id': chunk['id'], 'score': score})
    for word in inverted_index:
        inverted_index[word].sort(key=lambda x: x['score'], reverse=True)
    return inverted_index

def build_metadata_index(chunks):
    """Build O(1) lookup indexes for tags, category, used_in, entrypoints."""
    tag_index = {}
    category_index = {}
    used_in_index = {}
    entrypoint_ids = []

    for chunk in chunks:
        cid = chunk['id']
        for tag in chunk.get('tags', []):
            tag_index.setdefault(tag, []).append(cid)
        for cat in chunk.get('category', []):
            category_index.setdefault(cat, []).append(cid)
        for ui in chunk.get('used_in', []):
            used_in_index.setdefault(ui, []).append(cid)
        if chunk.get('entrypoint'):
            entrypoint_ids.append(cid)

    return {
        'tag_index':      tag_index,
        'category_index': category_index,
        'used_in_index':  used_in_index,
        'entrypoint_ids': entrypoint_ids,
    }

def _resolve_related_node(related_path, source_file_path, path_to_chunk_ids):
    """Resolve a relative related_node path to chunk_ids."""
    source_dir = os.path.dirname(source_file_path)
    # Try resolving relative to the source file's directory
    candidates = [
        os.path.normpath(os.path.join(source_dir, related_path)),
        os.path.normpath(os.path.join(source_dir, related_path + '.md')),
        os.path.normpath(os.path.join(source_dir, related_path + '.yaml')),
    ]
    for candidate in candidates:
        if candidate in path_to_chunk_ids:
            return path_to_chunk_ids[candidate]
    # Also try basename match
    basename = os.path.basename(related_path)
    for path, cids in path_to_chunk_ids.items():
        if os.path.basename(path) == basename or os.path.basename(path) == basename + '.md':
            return cids
    return []

def create_knowledge_graph_with_content(chunks, embeddings):
    """Build knowledge graph using embedding cosine similarity + YAML related_nodes."""
    nodes, edges = [], []

    # Build path -> [chunk_idx] index for related_nodes resolution
    path_to_chunk_ids = {}
    for chunk in chunks:
        fp = chunk.get('file_path', '')
        path_to_chunk_ids.setdefault(fp, []).append(chunk['id'])

    # Build chunk_id -> node_id index
    chunk_id_to_node_id = {}
    for i, chunk in enumerate(chunks):
        node_id = f"n{i + 1}"
        chunk_id_to_node_id[chunk['id']] = node_id
        nodes.append({
            'id': node_id,
            'chunk_id': chunk['id'],
            'type': chunk['type'],
            'label': chunk['section'],
            'tags': chunk.get('tags', []),
            'category': chunk.get('category', []),
            'used_in': chunk.get('used_in', []),
            'entrypoint': chunk.get('entrypoint', False),
        })
        if i > 0:
            edges.append({'from': f"n{i}", 'to': node_id, 'type': 'refers-to',
                          'weight': 0.9, 'evidence_chunk_id': chunk['id']})

    # Semantic edges from cosine similarity
    cosine_sim = embeddings @ embeddings.T
    for i in range(len(chunks)):
        for j in range(i + 1, len(chunks)):
            if cosine_sim[i, j] > 0.7:
                edges.append({'from': f"n{i + 1}", 'to': f"n{j + 1}", 'type': 'related-to',
                              'weight': float(cosine_sim[i, j]), 'evidence_chunk_id': chunks[i]['id']})

    # Explicit reference edges from companion YAML related_nodes
    seen_refs = set()
    for i, chunk in enumerate(chunks):
        src_node = f"n{i + 1}"
        for rel_path in chunk.get('related_nodes', []):
            target_cids = _resolve_related_node(rel_path, chunk['file_path'], path_to_chunk_ids)
            for tcid in target_cids:
                dst_node = chunk_id_to_node_id.get(tcid)
                if dst_node and dst_node != src_node:
                    key = (src_node, dst_node)
                    if key not in seen_refs:
                        seen_refs.add(key)
                        edges.append({'from': src_node, 'to': dst_node, 'type': 'references',
                                      'weight': 1.0, 'evidence_chunk_id': chunk['id']})

    for i, edge in enumerate(edges):
        edge['id'] = f'e{i+1}'
    return nodes, edges

def process_directory(directory_path):
    all_chunks = []

    # First pass: classify YAML files by their sibling source file type
    md_companion_yamls = set()   # .yaml next to .md  → merged into md chunks, skip standalone
    go_companion_yamls = set()   # .yaml next to .go  → process via process_go_yaml

    for root, _, files in os.walk(directory_path):
        for file in files:
            base = os.path.splitext(os.path.join(root, file))[0]
            if file.endswith('.md'):
                candidate = base + '.yaml'
                if os.path.exists(candidate):
                    md_companion_yamls.add(candidate)
            elif file.endswith('.go'):
                candidate = base + '.yaml'
                if os.path.exists(candidate):
                    go_companion_yamls.add(candidate)

    # Second pass: process files with correct handler
    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            if file.endswith('.md'):
                all_chunks.extend(process_md_file(file_path))
            elif file.endswith(('.yaml', '.yml')):
                if file_path in go_companion_yamls:
                    all_chunks.extend(process_go_yaml(file_path))
                elif file_path not in md_companion_yamls:
                    all_chunks.extend(process_yaml_file(file_path))

    return all_chunks

def build_knowledge_base(source_directory, model_name=EMBEDDING_MODEL):
    chunks_list = process_directory(source_directory)
    chunks_list.sort(key=lambda x: (x['file_path'], x['start_line']))
    for i, chunk in enumerate(chunks_list):
        chunk['id'] = f'c{i+1}'

    texts = [chunk['text'] for chunk in chunks_list]

    print("Building embeddings...")
    model, embeddings = create_embeddings(texts, model_name)

    print("Building BM25 index...")
    bm25 = build_bm25_index(chunks_list)

    print("Building FAISS index...")
    faiss_index = build_faiss_index(embeddings)

    print("Building inverted index (BM25 scores for SQLite)...")
    inverted_index = create_bm25_inverted_index(chunks_list, bm25)

    print("Building metadata index (tags/category/used_in)...")
    metadata_index = build_metadata_index(chunks_list)

    nodes_list, edges_list = create_knowledge_graph_with_content(chunks_list, embeddings)

    for edge in edges_list:
        if 'evidence_chunk_id' in edge:
            chunk = next((c for c in chunks_list if c['id'] == edge['evidence_chunk_id']), None)
            if chunk:
                edge['evidence'] = [{'file': chunk['file_path'], 'start_line': chunk['start_line'], 'end_line': chunk['end_line']}]

    return {
        "chunks": {item['id']: item for item in chunks_list},
        "nodes": {item['id']: item for item in nodes_list},
        "edges": {item['id']: item for item in edges_list},
        "inverted_index": inverted_index,
        "metadata_index": metadata_index,
        "bm25": bm25,
        "bm25_chunk_ids": [c['id'] for c in chunks_list],
        "faiss_index": faiss_index,
        "model_name": model_name,
    }

def save_knowledge_base_legacy(kb_data, output_dir="kb_data", save_json=True, save_pickle=True):
    if not (save_json or save_pickle): return
    os.makedirs(output_dir, exist_ok=True)
    if save_json: os.makedirs(os.path.join(output_dir, 'json'), exist_ok=True)
    if save_pickle: os.makedirs(os.path.join(output_dir, 'pkl'), exist_ok=True)

    legacy_data = {
        "chunks": kb_data.get("chunks", {}),
        "graph_nodes": kb_data.get("nodes", {}),
        "inverted_index": kb_data.get("inverted_index", {}),
        "graph_edges": kb_data.get("edges", {})
    }

    if save_json:
        for name, data in legacy_data.items():
            with open(os.path.join(output_dir, 'json', f"{name}.json"), 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        meta_idx = kb_data.get("metadata_index", {})
        with open(os.path.join(output_dir, 'json', 'metadata_index.json'), 'w', encoding='utf-8') as f:
            json.dump(meta_idx, f, ensure_ascii=False, indent=2)

    if save_pickle:
        for name, data in legacy_data.items():
            with open(os.path.join(output_dir, 'pkl', f"{name}.pkl"), 'wb') as f:
                pickle.dump(data, f)

        faiss_index = kb_data.get("faiss_index")
        if faiss_index is not None:
            faiss.write_index(faiss_index, os.path.join(output_dir, 'pkl', 'faiss.index'))

        bm25 = kb_data.get("bm25")
        if bm25 is not None:
            with open(os.path.join(output_dir, 'pkl', 'bm25.pkl'), 'wb') as f:
                pickle.dump(bm25, f)

        bm25_chunk_ids = kb_data.get("bm25_chunk_ids")
        if bm25_chunk_ids is not None:
            with open(os.path.join(output_dir, 'pkl', 'chunk_ids.pkl'), 'wb') as f:
                pickle.dump(bm25_chunk_ids, f)

        with open(os.path.join(output_dir, 'pkl', 'model_name.pkl'), 'wb') as f:
            pickle.dump(kb_data.get("model_name", EMBEDDING_MODEL), f)

        meta_idx = kb_data.get("metadata_index", {})
        with open(os.path.join(output_dir, 'pkl', 'metadata_index.pkl'), 'wb') as f:
            pickle.dump(meta_idx, f)

def save_kb_to_sqlite(kb_data, output_dir="sqlite_data"):
    os.makedirs(output_dir, exist_ok=True)
    db_path = os.path.join(output_dir, 'knowledge_base.sqlite')
    schema_path = os.path.join(output_dir, 'db_schema.json')
    if os.path.exists(db_path): os.remove(db_path)

    with open(schema_path, 'r', encoding='utf-8') as f: schema = json.load(f)
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("PRAGMA foreign_keys = ON;")

    for table in schema['tables']:
        cols = ", ".join([f'"{c["name"]}" {c["type"]}' for c in table["columns"]])
        pk = table.get("primary_key", [])
        pk_str = f', PRIMARY KEY({", ".join(pk)})' if pk else ''
        cursor.execute(f"CREATE TABLE {table['name']} ({cols}{pk_str})")

    files_map = {path: i + 1 for i, path in enumerate(sorted(list(set(c['file_path'] for c in kb_data['chunks'].values()))))}
    cursor.executemany("INSERT INTO files (id, path) VALUES (?, ?)", [(i, p) for p, i in files_map.items()])

    terms_map = {term: i + 1 for i, term in enumerate(sorted(kb_data['inverted_index'].keys()))}
    cursor.executemany("INSERT INTO terms (id, term) VALUES (?, ?)", [(i, t) for t, i in terms_map.items()])

    chunk_data = [(c['id'], files_map[c['file_path']], c['text'], c['section'], c['start_line'], c['end_line'], c['lang'], c['type']) for c in kb_data['chunks'].values()]
    cursor.executemany("INSERT INTO chunks VALUES (?, ?, ?, ?, ?, ?, ?, ?)", chunk_data)

    cursor.executemany("INSERT INTO nodes VALUES (?, ?, ?, ?)", [(n['id'], n['chunk_id'], n['type'], n['label']) for n in kb_data['nodes'].values()])

    edge_data = [(e['id'], e['from'], e['to'], e['type'], e.get('weight', 1.0)) for e in kb_data['edges'].values()]
    cursor.executemany("INSERT INTO edges VALUES (?, ?, ?, ?, ?)", edge_data)

    evidence_data = [(e['id'], e['evidence_chunk_id']) for e in kb_data['edges'].values() if 'evidence_chunk_id' in e]
    cursor.executemany("INSERT INTO edge_evidence VALUES (?, ?)", evidence_data)

    inverted_index_data = []
    for term, entries in kb_data['inverted_index'].items():
        term_id = terms_map.get(term)
        if term_id:
            for entry in entries:
                if entry['score'] > 0.01:
                    inverted_index_data.append((term_id, entry['chunk_id'], entry['score']))
    cursor.executemany("INSERT INTO inverted_index VALUES (?, ?, ?)", inverted_index_data)

    # Metadata index tables
    tag_rows = [(cid, tag) for tag, cids in kb_data.get('metadata_index', {}).get('tag_index', {}).items() for cid in cids]
    cursor.executemany("INSERT INTO chunk_tags (chunk_id, tag) VALUES (?, ?)", tag_rows)

    cat_rows = [(cid, cat) for cat, cids in kb_data.get('metadata_index', {}).get('category_index', {}).items() for cid in cids]
    cursor.executemany("INSERT INTO chunk_categories (chunk_id, category) VALUES (?, ?)", cat_rows)

    ui_rows = [(cid, ui) for ui, cids in kb_data.get('metadata_index', {}).get('used_in_index', {}).items() for cid in cids]
    cursor.executemany("INSERT INTO chunk_used_in (chunk_id, used_in) VALUES (?, ?)", ui_rows)

    for table in schema['tables']:
        if 'indexes' in table:
            for index in table['indexes']:
                cursor.execute(f"CREATE INDEX IF NOT EXISTS {index['name']} ON {table['name']} ({', '.join(index['columns'])})")

    conn.commit()
    cursor.execute("VACUUM;")
    cursor.execute("ANALYZE;")
    conn.close()

def generate_edge_types_doc(kb_data, output_dir="kb_data"):
    """Generates a markdown file documenting all unique edge types."""
    edge_types = sorted(list(set(edge['type'] for edge in kb_data['edges'].values())))

    content = "# Edge Types Documentation\n\n"
    content += "This document lists all unique edge types automatically discovered in the knowledge graph.\n\n"
    content += "Understanding these relationships is key to querying and interpreting the graph's structure.\n\n"

    for edge_type in edge_types:
        content += f"- `{edge_type}`\n"

    doc_path = os.path.join(output_dir, 'edge_types.md')
    with open(doc_path, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"Successfully generated edge types documentation at '{doc_path}'")


if __name__ == "__main__":
    print("Starting knowledge base generation...")
    source_path = './source'
    legacy_output_path = './kb_data'
    sqlite_output_path = './sqlite_data'

    kb_objects = build_knowledge_base(source_path)

    save_knowledge_base_legacy(kb_objects, output_dir=legacy_output_path, save_json=True, save_pickle=True)
    save_kb_to_sqlite(kb_objects, output_dir=sqlite_output_path)
    generate_edge_types_doc(kb_objects, output_dir=legacy_output_path)

    print("\n--- Generation Complete ---")
    print(f"Total chunks: {len(kb_objects['chunks'])}")
    print(f"Total nodes: {len(kb_objects['nodes'])}")
    print(f"Total edges: {len(kb_objects['edges'])}")

    meta = kb_objects.get('metadata_index', {})
    print(f"Unique tags: {len(meta.get('tag_index', {}))}")
    print(f"Unique categories: {len(meta.get('category_index', {}))}")
    print(f"Unique used_in: {len(meta.get('used_in_index', {}))}")
    print(f"Entrypoints: {len(meta.get('entrypoint_ids', []))}")

    print(f"\nSuccessfully created legacy data files in '{legacy_output_path}/'")
    print(f"Successfully created SQLite DB in '{sqlite_output_path}/'")

    db_size = os.path.getsize(os.path.join(sqlite_output_path, 'knowledge_base.sqlite'))
    print(f"SQLite database size: {db_size / 1024 / 1024:.2f} MB")
