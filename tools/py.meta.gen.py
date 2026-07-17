#!/usr/bin/env python3
"""py.meta.gen.py — Companion YAML skeleton generator for Python source files.

Parses Python source files (via the `ast` module) and generates a .yaml companion
following py.meta.schema.yaml.

Auto-filled fields:
  - module, entrypoint
  - objects: name, kind, receiver, decorators, references
  - description: extracted from module/class/function docstrings
  - tags: suggested from file path, imports, and naming conventions (review before use)

Semantic fields left empty for human completion:
  - category, used_in, related_nodes, implements

Usage:
    python tools/py.meta.gen.py <file.py> [<file.py> ...]
    python tools/py.meta.gen.py --dir <directory> [--recursive] [--overwrite]

Options:
    --dir         Process all .py files in directory (default: non-recursive)
    --recursive   Recurse into subdirectories (use with --dir); skips
                  p_venv/__pycache__/.git/.idea/.pytest_cache/node_modules
    --overwrite   Overwrite existing .yaml files (default: skip)
    --merge       Update auto fields while preserving manual fields (tags,
                  category, used_in, related_nodes, implements)
    --skip-tests  Skip test_*.py / *_test.py files (default: include)
    --dry-run     Print what would be generated without writing files
"""

import ast
import re
import sys
import argparse
from pathlib import Path

try:
    import yaml
except ImportError:
    print("PyYAML not found. Install with: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

# Allowed tag values from py.meta.schema.yaml — same vocabulary as go.meta.schema.yaml
# so tag-based graph queries work across both languages.
_ALLOWED_TAGS = {
    "relay", "compliance", "workflow", "cictor", "schema", "parser", "guard",
    "core", "doc", "interface", "gateway", "builder", "test", "meta",
    "orchestrator", "decision", "reflector", "context", "validator", "executor",
    "hook", "template", "fallback", "session", "metrics", "storage", "loader",
    "renderer", "platform-engineering", "ci-cd", "ecosystem",
}

# Directories skipped during --dir --recursive scans.
_SKIP_DIRS = {"p_venv", "__pycache__", ".git", ".idea", ".pytest_cache", "node_modules"}

# Fallback stdlib root list for Python < 3.10 (no sys.stdlib_module_names).
_FALLBACK_STDLIB = {
    "abc", "argparse", "ast", "asyncio", "base64", "collections", "configparser",
    "contextlib", "copy", "csv", "dataclasses", "datetime", "decimal", "enum",
    "functools", "glob", "hashlib", "io", "itertools", "json", "logging", "math",
    "multiprocessing", "os", "pathlib", "pickle", "platform", "random", "re",
    "shutil", "socket", "sqlite3", "string", "subprocess", "sys", "tempfile",
    "textwrap", "threading", "time", "traceback", "typing", "unittest", "urllib",
    "uuid", "warnings", "xml", "zipfile",
}


def _stdlib_set() -> set[str]:
    names = getattr(sys, "stdlib_module_names", None)
    return set(names) if names else set(_FALLBACK_STDLIB)


# ---------------------------------------------------------------------------
# Import parsing
# ---------------------------------------------------------------------------

def _parse_imports(tree: ast.Module) -> dict[str, str]:
    """Return {local_alias: fully_qualified_target} for module-level imports.

    `import yaml`            -> {"yaml": "yaml"}
    `import numpy as np`     -> {"np": "numpy"}
    `from pathlib import Path` -> {"Path": "pathlib.Path"}
    `from . import foo`      -> {"foo": ".foo"}  (relative — treated as local/non-stdlib)
    """
    imports: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    imports[alias.asname] = alias.name
                else:
                    top = alias.name.split(".")[0]
                    imports[top] = top
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                origin = "." * node.level + (node.module or "")
                for alias in node.names:
                    local = alias.asname or alias.name
                    imports[local] = f"{origin}.{alias.name}"
            else:
                module = node.module or ""
                for alias in node.names:
                    local = alias.asname or alias.name
                    imports[local] = f"{module}.{alias.name}" if module else alias.name
    return imports


def _is_stdlib(target: str, stdlib: set[str]) -> bool:
    if not target or target.startswith("."):
        return False
    return target.split(".")[0] in stdlib


# ---------------------------------------------------------------------------
# Reference extraction
# ---------------------------------------------------------------------------

def _iter_subtree(node: ast.AST, skip_kinds: tuple = ()):
    stack = list(ast.iter_child_nodes(node))
    while stack:
        n = stack.pop()
        if skip_kinds and isinstance(n, skip_kinds):
            continue
        yield n
        stack.extend(ast.iter_child_nodes(n))


def _extract_refs(node: ast.AST, imports: dict[str, str], stdlib: set[str],
                   skip_kinds: tuple = ()) -> list[str]:
    """Find non-stdlib references in node's subtree.

    Two passes mirroring go.meta.gen.py's approach:
    1. Attribute access on an imported module alias: yaml.safe_load -> "yaml.safe_load"
    2. Bare use of a from-imported name: Path(...) where "from pathlib import Path"
       -> "pathlib.Path" (filtered out if the origin is stdlib)
    """
    seen: dict[str, None] = {}
    for n in _iter_subtree(node, skip_kinds):
        if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name):
            alias = n.value.id
            target = imports.get(alias)
            if target and not _is_stdlib(target, stdlib):
                seen[f"{target}.{n.attr}"] = None
        elif isinstance(n, ast.Name):
            target = imports.get(n.id)
            if target and "." in target and not _is_stdlib(target, stdlib):
                seen[target] = None
    return list(seen)


# ---------------------------------------------------------------------------
# Decorator / docstring helpers
# ---------------------------------------------------------------------------

def _dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _extract_calls(node: ast.AST, imports: dict[str, str], stdlib: set[str]) -> list[str]:
    """Extract non-stdlib function/method calls from the given AST node subtree.

    Resolves through imports:
    - yaml.safe_load(...)  -> yaml.safe_load  (from: import yaml)
    - Path(...)            -> pathlib.Path    (from: from pathlib import Path)
    - local_func(...)      -> local_func      (same-module, kept for graph edges)
    """
    calls: dict[str, None] = {}
    for n in _iter_subtree(node):
        if not isinstance(n, ast.Call):
            continue
        func = n.func
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            alias = func.value.id
            target = imports.get(alias)
            if target:
                if not _is_stdlib(target, stdlib):
                    calls[f"{target}.{func.attr}"] = None
            else:
                # Local variable or same-module object — keep for intra-module edges
                calls[f"{alias}.{func.attr}"] = None
        elif isinstance(func, ast.Name):
            target = imports.get(func.id)
            if target:
                if not _is_stdlib(target, stdlib):
                    calls[target] = None
            elif func.id[0].isupper() or func.id.startswith("_"):
                # Capitalized = likely class/constructor; underscore = module-private helper
                calls[func.id] = None
    return sorted(calls)


def _decorator_name(node: ast.AST) -> str:
    if isinstance(node, ast.Call):
        return _dotted_name(node.func)
    return _dotted_name(node)


def _decorators(node) -> list[str]:
    return [d for d in (_decorator_name(n) for n in node.decorator_list) if d]


def _clean_doc(doc: str | None) -> str:
    if not doc:
        return ""
    lines = [line.strip() for line in doc.strip().splitlines() if line.strip()]
    return " ".join(lines)


def _has_main_guard(tree: ast.Module) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.If):
            test = node.test
            if (isinstance(test, ast.Compare) and isinstance(test.left, ast.Name)
                    and test.left.id == "__name__"):
                return True
    return False


# ---------------------------------------------------------------------------
# Tag suggestion
# ---------------------------------------------------------------------------

def _suggest_tags(py_file: Path, imports: dict[str, str], objects: list[dict]) -> list[str]:
    """Suggest tags from file path, imports, and object naming conventions.
    Returns a sorted list of allowed tag values (see py.meta.schema.yaml).
    These are suggestions — review and trim before committing the YAML.
    """
    tags: set[str] = set()
    path_str = str(py_file).replace("\\", "/")
    filename = py_file.name

    if "/tools/" in path_str or path_str.startswith("tools/"):
        tags.add("builder")
    if filename.startswith("test_") or filename.endswith("_test.py"):
        tags.add("test")
    if "mcp-server" in path_str or filename == "server.py":
        tags.update(["gateway", "interface"])
    if filename == "make_source.py":
        tags.update(["builder", "core"])

    origins = set(imports.values())
    if any(o.split(".")[0] == "sqlite3" for o in origins):
        tags.add("storage")
    if any(o.split(".")[0] == "argparse" for o in origins):
        tags.add("core")

    for obj in objects:
        name = obj["name"]
        if re.match(r"^[Vv]alidate", name):
            tags.add("validator")
        if re.match(r"^([Ee]xecute|[Rr]un)", name):
            tags.add("executor")
        if re.match(r"^[Ll]oad", name):
            tags.add("loader")
        if re.search(r"^hook|Hook$", name):
            tags.add("hook")
        if re.search(r"[Mm]etric", name):
            tags.add("metrics")
        if re.search(r"[Ss]chema", name):
            tags.add("schema")
        if re.match(r"^[Pp]arse", name):
            tags.add("parser")
        if "mcp.tool" in obj.get("decorators", []):
            tags.add("interface")

    return sorted(tags & _ALLOWED_TAGS)


# ---------------------------------------------------------------------------
# Object parsing
# ---------------------------------------------------------------------------

def _parse_objects(tree: ast.Module, imports: dict[str, str], stdlib: set[str]) -> list[dict]:
    objects: list[dict] = []

    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            bases = [b for b in (_dotted_name(n) for n in node.bases) if b]
            objects.append({
                "name": node.name,
                "kind": "class",
                "decorators": _decorators(node),
                "description": _clean_doc(ast.get_docstring(node)),
                "implements": bases,
                "references": _extract_refs(node, imports, stdlib,
                                             skip_kinds=(ast.FunctionDef, ast.AsyncFunctionDef)),
            })
            for sub in node.body:
                if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    objects.append({
                        "name": sub.name,
                        "kind": "method",
                        "receiver": node.name,
                        "decorators": _decorators(sub),
                        "description": _clean_doc(ast.get_docstring(sub)),
                        "references": _extract_refs(sub, imports, stdlib),
                        "calls": _extract_calls(sub, imports, stdlib),
                    })

        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            objects.append({
                "name": node.name,
                "kind": "function",
                "decorators": _decorators(node),
                "description": _clean_doc(ast.get_docstring(node)),
                "references": _extract_refs(node, imports, stdlib),
                "calls": _extract_calls(node, imports, stdlib),
            })

        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    objects.append({"name": target.id, "kind": "const",
                                     "description": "", "references": []})

    return objects


# ---------------------------------------------------------------------------
# Module name resolution
# ---------------------------------------------------------------------------

def _module_name(py_file: Path) -> str:
    """Walk up while sibling __init__.py files exist (package convention)."""
    parts = [py_file.stem]
    parent = py_file.parent
    while (parent / "__init__.py").exists():
        parts.insert(0, parent.name)
        parent = parent.parent
    return ".".join(parts)


# ---------------------------------------------------------------------------
# Main generator
# ---------------------------------------------------------------------------

def generate(py_file: Path) -> dict:
    source = py_file.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(py_file))
    stdlib = _stdlib_set()
    imports = _parse_imports(tree)
    objects = _parse_objects(tree, imports, stdlib)

    return {
        "module": _module_name(py_file),
        "description": _clean_doc(ast.get_docstring(tree)),
        "tags": _suggest_tags(py_file, imports, objects),
        "category": [],
        "used_in": [],
        "entrypoint": _has_main_guard(tree),
        "related_nodes": [],
        "objects": objects,
    }


def _merge_data(new_data: dict, old_data: dict) -> dict:
    """Merge freshly generated data into an existing YAML.

    Auto fields (always updated from source):
      module, entrypoint, objects.references, objects.kind, objects.receiver,
      objects.decorators

    Description fields (updated only if a docstring exists in source):
      description (file-level), objects[].description
      If the new description is empty, the existing value is preserved.

    Manual fields (never touched):
      tags, category, used_in, related_nodes, objects[].implements

    Objects:
      - New objects (added to source) -> appended
      - Removed objects (deleted from source) -> dropped
      - Existing objects -> merged per field rules above
    """
    merged = dict(new_data)

    merged["tags"] = old_data.get("tags", new_data.get("tags", []))
    merged["category"] = old_data.get("category", [])
    merged["used_in"] = old_data.get("used_in", [])
    merged["related_nodes"] = old_data.get("related_nodes", [])

    if not merged.get("description"):
        merged["description"] = old_data.get("description", "")

    old_by_name: dict[str, dict] = {o["name"]: o for o in old_data.get("objects", [])}
    merged_objects = []
    for new_obj in new_data.get("objects", []):
        name = new_obj["name"]
        if name in old_by_name:
            old_obj = old_by_name[name]
            obj = dict(new_obj)
            if obj.get("kind") == "class":
                obj["implements"] = old_obj.get("implements", [])
            if not obj.get("description"):
                obj["description"] = old_obj.get("description", "")
        else:
            obj = new_obj
        merged_objects.append(obj)

    merged["objects"] = merged_objects
    return merged


def _write_yaml(data: dict, path: Path) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write("---\n")
        yaml.dump(data, f, allow_unicode=True, default_flow_style=False, sort_keys=False)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate companion YAML skeletons for Python source files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("files", nargs="*", metavar="FILE", help="Python source files to process")
    parser.add_argument("--dir", metavar="DIR", help="Process all .py files in DIR")
    parser.add_argument("--recursive", action="store_true",
                        help="Recurse into subdirectories (use with --dir)")
    parser.add_argument("--overwrite", action="store_true",
                        help="Overwrite existing YAML files completely")
    parser.add_argument("--merge", action="store_true",
                        help="Update auto fields while preserving manual fields "
                             "(tags, category, used_in, related_nodes, implements). "
                             "Implies --overwrite for existing files.")
    parser.add_argument("--skip-tests", action="store_true",
                        help="Skip test_*.py / *_test.py files")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print actions without writing files")
    args = parser.parse_args()

    files: list[Path] = [Path(f) for f in args.files]
    if args.dir:
        d = Path(args.dir)
        glob = d.rglob("*.py") if args.recursive else d.glob("*.py")
        for f in glob:
            if args.recursive and _SKIP_DIRS & set(f.relative_to(d).parts[:-1]):
                continue
            files.append(f)

    if not files:
        parser.print_help()
        sys.exit(1)

    generated = merged_count = skipped = errors = 0
    for py_file in sorted(set(files)):
        if not py_file.exists():
            print(f"NOT FOUND: {py_file}", file=sys.stderr)
            errors += 1
            continue
        if args.skip_tests and (py_file.name.startswith("test_") or py_file.name.endswith("_test.py")):
            continue

        yaml_file = py_file.with_suffix(".yaml")
        existing = yaml_file.exists()

        if existing and not args.overwrite and not args.merge:
            print(f"SKIP (exists): {yaml_file}")
            skipped += 1
            continue

        try:
            data = generate(py_file)
        except SyntaxError as e:
            print(f"ERROR: {py_file}: {e}", file=sys.stderr)
            errors += 1
            continue

        if existing and args.merge:
            try:
                with open(yaml_file) as fh:
                    old_data = yaml.safe_load(fh) or {}
                data = _merge_data(data, old_data)
                action = "MERGED"
                merged_count += 1
            except Exception as e:
                print(f"ERROR reading existing {yaml_file}: {e}", file=sys.stderr)
                errors += 1
                continue
        else:
            action = "GENERATED"
            generated += 1

        obj_count = len(data["objects"])
        ref_count = sum(len(o.get("references", [])) for o in data["objects"])

        if args.dry_run:
            print(f"DRY-RUN ({action}): {yaml_file}  [{obj_count} objects, {ref_count} refs]")
        else:
            _write_yaml(data, yaml_file)
            print(f"{action}: {yaml_file}  [{obj_count} objects, {ref_count} refs]")

    summary = f"\nDone: {generated} generated, {merged_count} merged, {skipped} skipped, {errors} errors"
    print(summary)
    if errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
