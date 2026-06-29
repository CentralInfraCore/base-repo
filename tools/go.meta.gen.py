#!/usr/bin/env python3
"""go.meta.gen.py — Companion YAML skeleton generator for Go source files.

Parses Go source files and generates a .yaml companion following go.meta.schema.yaml.
Auto-filled fields:
  - package, entrypoint
  - objects: name, kind, receiver, references
  - description: extracted from Go doc comments (// lines before declaration)
  - tags: suggested from file path, imports, and naming conventions (review before use)

Semantic fields left empty for human completion:
  - category, used_in, related_nodes, implements

Usage:
    python tools/go.meta.gen.py <file.go> [<file.go> ...]
    python tools/go.meta.gen.py --dir <directory> [--recursive] [--overwrite]

Options:
    --dir         Process all .go files in directory (default: non-recursive)
    --recursive   Recurse into subdirectories (use with --dir)
    --overwrite   Overwrite existing .yaml files (default: skip)
    --skip-tests  Skip _test.go files (default: include)
    --dry-run     Print what would be generated without writing files
"""

import re
import sys
import argparse
from pathlib import Path

try:
    import yaml
except ImportError:
    print("PyYAML not found. Install with: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

# Allowed tag values from go.meta.schema.yaml — used to filter suggestions.
_ALLOWED_TAGS = {
    "relay", "compliance", "workflow", "cictor", "schema", "parser", "guard",
    "core", "doc", "interface", "gateway", "builder", "test", "meta",
    "orchestrator", "decision", "reflector", "context", "validator", "executor",
    "hook", "template", "fallback", "session", "metrics", "storage", "loader",
    "renderer", "legal", "license", "platform-engineering", "ci-cd", "ecosystem",
}

# Known first path segments of Go standard library packages.
# Used to filter out stdlib imports when deciding if a reference is external.
# Detection is path-based (not alias-based) to avoid false positives from
# project-internal packages that happen to use common alias names like "types".
_STDLIB_ROOTS = {
    # single-segment stdlib
    "builtin", "unsafe",
    # multi-segment stdlib roots (first path component)
    "archive", "bufio", "bytes", "compress", "container", "context",
    "crypto", "database", "debug", "embed", "encoding", "errors", "expvar",
    "flag", "fmt", "go", "hash", "html", "image", "io", "log", "math",
    "mime", "net", "os", "path", "plugin", "reflect", "regexp", "runtime",
    "sort", "strconv", "strings", "sync", "syscall", "testing", "text",
    "time", "unicode", "unique", "slices", "maps", "cmp",
}


# ---------------------------------------------------------------------------
# Source cleaning
# ---------------------------------------------------------------------------

def _remove_comments(source: str) -> str:
    """Remove // and /* */ comments."""
    source = re.sub(r'/\*.*?\*/', '', source, flags=re.DOTALL)
    source = re.sub(r'//[^\n]*', '', source)
    return source


def _remove_strings(source: str) -> str:
    """Replace string/rune literals with placeholders to avoid false matches.
    Must be called after comment removal so apostrophes in comments don't confuse
    the rune literal pattern."""
    # Raw strings: `...`
    source = re.sub(r'`[^`]*`', '``', source, flags=re.DOTALL)
    # Interpreted strings: "..."
    source = re.sub(r'"(?:[^"\\]|\\.)*"', '""', source)
    # Rune literals: 'x' '\n' '\u0041' — max ~6 chars, never multiline
    source = re.sub(r"'(?:[^'\\]|\\.){1,6}'", "''", source)
    return source


def _clean(source: str) -> str:
    # Comments first — prevents apostrophes in comments from poisoning rune literal regex
    return _remove_strings(_remove_comments(source))


# ---------------------------------------------------------------------------
# Block extraction (brace-matching)
# ---------------------------------------------------------------------------

def _extract_block_content(source: str, open_pos: int) -> str:
    """Return content between matching { } starting at open_pos (the '{')."""
    depth = 0
    content = []
    for i in range(open_pos, len(source)):
        c = source[i]
        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                break
        elif depth > 0:
            content.append(c)
    return ''.join(content)


# ---------------------------------------------------------------------------
# Import parsing
# ---------------------------------------------------------------------------

def _parse_imports(source: str) -> dict[str, str]:
    """Return {local_alias: import_path} for all imports in source.
    Parses comment-stripped source so inline comments don't interfere,
    but keeps string contents so import paths remain readable."""
    imports: dict[str, str] = {}
    no_comments = _remove_comments(source)  # keep strings intact

    # Single: import "path"  or  import alias "path"
    for m in re.finditer(r'^\s*import\s+(?:(\w+)\s+)?"([^"]+)"', no_comments, re.MULTILINE):
        alias = m.group(1) or m.group(2).split('/')[-1]
        imports[alias] = m.group(2)

    # Block: import ( ... )
    block_m = re.search(r'\bimport\s*\(([^)]+)\)', no_comments, re.DOTALL)
    if block_m:
        for line in block_m.group(1).splitlines():
            line = line.strip()
            if not line:
                continue
            # alias "path"
            m = re.match(r'(\w+|_|\.)\s+"([^"]+)"', line)
            if m:
                alias = m.group(1) if m.group(1) not in ('_', '.') else m.group(2).split('/')[-1]
                imports[alias] = m.group(2)
                continue
            # "path"
            m = re.match(r'"([^"]+)"', line)
            if m:
                alias = m.group(1).split('/')[-1]
                imports[alias] = m.group(1)

    return imports


def _find_module_name(go_file: Path) -> str:
    """Walk up from go_file to find go.mod and return the module name."""
    for parent in go_file.parents:
        mod = parent / "go.mod"
        if mod.exists():
            for line in mod.read_text().splitlines():
                m = re.match(r'^\s*module\s+(\S+)', line)
                if m:
                    return m.group(1)
    return ""


def _is_stdlib_path(path: str) -> bool:
    """True if the import path is a Go standard library package.
    Stdlib paths have no dots and their first segment is a known stdlib root."""
    if '.' in path:
        return False  # third-party always has dots (github.com, gopkg.in, etc.)
    return path.split('/')[0] in _STDLIB_ROOTS


def _is_external(pkg: str, imports: dict[str, str], module_name: str = "") -> bool:
    """True if pkg refers to a non-stdlib import.
    Includes both third-party (github.com/...) and same-module cross-package refs
    (e.g. centralrelay/core/cabinet). Only pure stdlib is excluded."""
    if pkg not in imports:
        return False
    return not _is_stdlib_path(imports[pkg])


def _extract_interface_methods(body: str) -> list[str]:
    """Extract exported method names from an interface body."""
    methods = []
    for m in re.finditer(r'^\s+([A-Z]\w*)\s*\(', body, re.MULTILINE):
        methods.append(m.group(1))
    return sorted(set(methods))


def _extract_calls(body: str, refs: list[str] | None = None) -> list[str]:
    """Extract function/method calls from function body with type resolution.

    First extracts method names from body (Set, Query, etc).
    Then resolves types using references (cabinet.Cabinet.Set, sql.DB.Query, etc).

    Examples:
        body: "s.Set(db.Query())"  refs: ["cabinet.Cabinet.Set", "sql.DB.Query"]
        → ["cabinet.Cabinet.Set", "sql.DB.Query"]

    Falls back to untyped calls if refs unavailable:
        body: "s.Set(db.Query())"  refs: None
        → ["Set", "Query"]
    """
    calls = []
    call_names = set()

    # Extract bare method/function names
    # First pattern: pkg.Name()
    for m in re.finditer(r'\b\w+\.([A-Z]\w*)\s*\(', body):
        call_names.add(m.group(1))

    # Second pattern: standalone Name()
    for m in re.finditer(r'\b([A-Z]\w*)\s*\(', body):
        call_names.add(m.group(1))

    # Type resolution: match call names against references
    if refs:
        typed_calls = []
        for ref in refs:
            # ref format: "cabinet.Cabinet.Set", extract the method name
            method_name = ref.split('.')[-1]  # "Set" from "cabinet.Cabinet.Set"
            if method_name in call_names:
                typed_calls.append(ref)

        # Return typed calls if found, otherwise fall back to bare names
        if typed_calls:
            return sorted(set(typed_calls))

    # Fallback: return untyped call names
    return sorted(call_names) if call_names else []


def _extract_param_types(params_str: str, imports: dict[str, str], module_name: str = "") -> dict[str, str]:
    """Extract {param_name: pkg_alias} from function parameter list.

    Examples:
        "s *Service, db *sql.DB" -> {"s": "Service", "db": "sql"}
        "ops nexusgit.GitOps" -> {"ops": "nexusgit.GitOps"}
    """
    result: dict[str, str] = {}
    if not params_str:
        return result

    # Split by comma, but handle nested parens (e.g., func types)
    parts = []
    current = []
    depth = 0
    for c in params_str:
        if c == '(':
            depth += 1
        elif c == ')':
            depth -= 1
        elif c == ',' and depth == 0:
            parts.append(''.join(current).strip())
            current = []
            continue
        current.append(c)
    if current:
        parts.append(''.join(current).strip())

    # Parse each parameter: [*]pkg.Type or [*]Type
    for part in parts:
        if not part or part.startswith('...'):
            continue

        # Extract type: skip pointer, handle []
        type_part = re.sub(r'^[\[\]*]+', '', part).strip()

        # Extract param name: "s *Service" → name="s", type="Service"
        m = re.match(r'^(\w+)\s+([\w.]+)$', type_part)
        if m:
            param_name = m.group(1)
            param_type = m.group(2)
            result[param_name] = param_type

    return result


def _extract_local_typed_vars(text: str, imports: dict[str, str], module_name: str = "") -> dict[str, str]:
    """Return {var_name: pkg_alias} for explicitly typed local variable declarations.

    Recognises these Go patterns:
        var db *sql.DB          -> {"db": "sql"}
        var c http.Client       -> {"c": "http"}
        var r []types.Relay     -> {"r": "types"}

    Only variables whose type package is a non-stdlib import are included.
    Short declarations (:=) are intentionally not handled — too fragile without AST.
    """
    result: dict[str, str] = {}
    # var <name> [*[]][<pkg>.<Type>]
    pattern = re.compile(r'\bvar\s+(\w+)\s+(?:\[\]|\*)*(\w+)\.([A-Z]\w*)')
    for m in pattern.finditer(text):
        var_name, pkg = m.group(1), m.group(2)
        if _is_external(pkg, imports, module_name):
            result[var_name] = pkg
    return result


def _extract_refs(text: str, imports: dict[str, str], module_name: str = "",
                   param_types: dict[str, str] | None = None,
                   receiver_type: str | None = None,
                   receiver_name: str = 's') -> list[str]:
    """Find non-stdlib pkg.Name references in text.

    Three passes:
    1. Direct package references: pkg.ExportedName  (types, funcs, consts)
    2. Typed variable method calls: var db *sql.DB → db.QueryRow → sql.QueryRow
    3. Parameter/receiver method calls: func f(s *Service) { s.Method() } → Service.Method
    """
    seen: dict[str, None] = {}  # ordered set preserving insertion order

    # Pass 1 — direct: json.Marshal, relay.Actor, http.NewRequest, ...
    for m in re.finditer(r'\b(\w+)\.([A-Z]\w*)', text):
        pkg, name = m.group(1), m.group(2)
        if _is_external(pkg, imports, module_name):
            seen[f"{pkg}.{name}"] = None

    # Pass 2 — typed variable methods: var db *sql.DB → db.QueryRow()
    local_vars = _extract_local_typed_vars(text, imports, module_name)
    for m in re.finditer(r'\b(\w+)\.([A-Z]\w*)\s*\(', text):
        var_name, method = m.group(1), m.group(2)
        pkg = local_vars.get(var_name)
        if pkg:
            seen[f"{pkg}.{method}"] = None

    # Pass 3 — parameter/receiver method calls
    # param_types: {"s": "Service", "ops": "nexusgit.GitOps"}
    # receiver_type: "Service" (for methods), receiver_name: "s"
    if param_types:
        local_vars.update(param_types)
    if receiver_type:
        local_vars[receiver_name] = receiver_type  # implicit receiver, e.g., s *relayServer → s: relayServer

    for m in re.finditer(r'\b(\w+)\.([A-Z]\w*)\s*\(', text):
        var_name, method = m.group(1), m.group(2)
        type_name = local_vars.get(var_name)
        if type_name and '.' in type_name:
            # Already has package: "nexusgit.GitOps"
            seen[f"{type_name}.{method}"] = None
        elif type_name and _is_external(type_name, imports, module_name):
            # Type is a local package: "Service" → resolve via imports
            # This would need symbol table, skip for now
            pass

    return list(seen)


# ---------------------------------------------------------------------------
# Doc comment extraction
# ---------------------------------------------------------------------------

def _extract_doc_comments(source: str) -> dict[str, str]:
    """Extract Go doc comments for top-level declarations.

    Matches contiguous `//` comment lines immediately preceding a declaration
    and returns {identifier_name: comment_text}.

    Examples:
        // config holds the application configuration.
        type config struct { ... }
        -> {"config": "config holds the application configuration."}

        // NewLoader creates a new Loader instance.
        func NewLoader(source IaCSource) *Loader {
        -> {"NewLoader": "NewLoader creates a new Loader instance."}
    """
    result: dict[str, str] = {}
    pattern = re.compile(
        r'((?:^[ \t]*//[^\n]*\n)+)'        # group 1: contiguous doc comment lines
        r'[ \t]*(?:type|func|var|const)\s+'  # declaration keyword
        r'(?:\([^)]*\)\s*)?'                 # optional method receiver
        r'(\w+)',                            # group 2: identifier name
        re.MULTILINE,
    )
    for m in pattern.finditer(source):
        comment_block = m.group(1)
        name = m.group(2)
        lines = []
        for line in comment_block.splitlines():
            cleaned = re.sub(r'^\s*//\s?', '', line).strip()
            if cleaned:
                lines.append(cleaned)
        if lines:
            result[name] = ' '.join(lines)
    return result


def _extract_package_doc(source: str) -> str:
    """Extract the package-level doc comment (// lines before 'package NAME')."""
    m = re.search(r'((?:^[ \t]*//[^\n]*\n)+)[ \t]*package\s+\w+', source, re.MULTILINE)
    if not m:
        return ""
    lines = []
    for line in m.group(1).splitlines():
        cleaned = re.sub(r'^\s*//\s?', '', line).strip()
        if cleaned:
            lines.append(cleaned)
    return ' '.join(lines)


# ---------------------------------------------------------------------------
# Tag suggestion
# ---------------------------------------------------------------------------

def _suggest_tags(go_file: Path, imports: dict[str, str], objects: list[dict]) -> list[str]:
    """Suggest tags from file path, imports, and object naming conventions.

    Returns a sorted list of allowed tag values (see go.meta.schema.yaml).
    These are suggestions — review and trim before committing the YAML.
    """
    tags: set[str] = set()
    path_str = str(go_file).replace('\\', '/')
    filename = go_file.name

    # --- file path hints ---
    if '/cmd/' in path_str or filename == 'main.go':
        tags.update(['core', 'gateway'])
    if '/tools/' in path_str:
        tags.add('builder')
    if filename.endswith('_test.go'):
        tags.add('test')
    if '/core/' in path_str:
        tags.add('core')

    # --- import hints ---
    import_paths = set(imports.values())
    if any('net/http' in p for p in import_paths):
        tags.add('interface')
    if any('database/sql' in p or p.endswith('/sql') for p in import_paths):
        tags.add('storage')
    if any(p == 'testing' for p in import_paths):
        tags.add('test')
    if any('metric' in p.lower() or 'prometheus' in p.lower() for p in import_paths):
        tags.add('metrics')

    # --- object naming convention hints ---
    for obj in objects:
        name = obj['name']
        if re.match(r'^Validate', name):
            tags.add('validator')
        if re.match(r'^Execute', name):
            tags.add('executor')
        if re.match(r'^Load', name):
            tags.add('loader')
        if re.search(r'Handler$', name):
            tags.add('interface')
        if re.search(r'Server$', name):
            tags.add('interface')
        if re.search(r'Store$|Repository$', name):
            tags.add('storage')
        if re.search(r'[Mm]etric', name):
            tags.add('metrics')
        if re.search(r'[Ss]chema', name):
            tags.add('schema')
        if re.match(r'^Parse|^Parser', name) or name.endswith('Parser'):
            tags.add('parser')
        if re.match(r'^Hook', name) or name.endswith('Hook'):
            tags.add('hook')

    # filter to allowed values only
    return sorted(tags & _ALLOWED_TAGS)


# ---------------------------------------------------------------------------
# Object parsing
# ---------------------------------------------------------------------------

def _parse_objects(source: str, imports: dict[str, str], module_name: str = "") -> list[dict]:
    objects: list[dict] = []
    clean = _clean(source)
    doc = _extract_doc_comments(source)

    # --- structs ---
    for m in re.finditer(r'\btype\s+(\w+)\s+struct\s*\{', clean):
        name = m.group(1)
        body = _extract_block_content(clean, m.end() - 1)
        # Struct fields could have types, but they're just declarations
        # Extract refs from field types
        refs = _extract_refs(body, imports, module_name)
        obj: dict = {"name": name, "kind": "struct",
                     "description": doc.get(name, ""),
                     "implements": [], "references": refs}
        objects.append(obj)

    struct_names = {o["name"] for o in objects}

    # --- interfaces ---
    for m in re.finditer(r'\btype\s+(\w+)\s+interface\s*\{', clean):
        name = m.group(1)
        body = _extract_block_content(clean, m.end() - 1)
        refs = _extract_refs(body, imports, module_name)
        methods = _extract_interface_methods(body)
        objects.append({"name": name, "kind": "interface",
                        "description": doc.get(name, ""), "references": refs,
                        "methods": methods})

    iface_names = {o["name"] for o in objects if o["kind"] == "interface"}

    # --- type aliases (not struct/interface) ---
    for m in re.finditer(r'\btype\s+(\w+)\s+(?!struct\b|interface\b)(\S+)', clean, re.MULTILINE):
        name = m.group(1)
        if name in struct_names or name in iface_names:
            continue
        underlying = m.group(2)
        refs = _extract_refs(underlying, imports, module_name)
        objects.append({"name": name, "kind": "type",
                        "description": doc.get(name, ""), "references": refs})

    # --- funcs and methods ---
    func_re = re.compile(
        r'\bfunc\s+'
        r'(?:\(\s*(\w+)\s+\*?(\w+)\s*\)\s*)?'   # group 1: receiver name, group 2: receiver type (optional)
        r'(\w+)\s*'                               # group 3: func name
        r'\(([^)]*(?:\([^)]*\)[^)]*)*)\)'        # group 4: params
        r'([^{]*)',                               # group 5: return types
        re.MULTILINE,
    )
    for m in func_re.finditer(clean):
        recv_name = m.group(1)
        recv_type = m.group(2)
        func_name = m.group(3)
        params = m.group(4) or ''
        returns = m.group(5) or ''
        brace_pos = clean.find('{', m.end())
        body = _extract_block_content(clean, brace_pos) if brace_pos != -1 else ''

        # Extract parameter types and pass to _extract_refs
        param_types = _extract_param_types(params, imports, module_name)
        refs = _extract_refs(f"{params} {returns} {body}", imports, module_name,
                            param_types=param_types, receiver_type=recv_type,
                            receiver_name=recv_name or 's')

        # Extract function/method calls from body with type resolution
        # Pass refs for type resolution: match call names against full refs
        calls = _extract_calls(body, refs)

        if recv_type:
            objects.append({
                "name": func_name,
                "kind": "method",
                "receiver": recv_type,
                "description": doc.get(func_name, ""),
                "references": refs,
                "calls": calls,
            })
        else:
            objects.append({
                "name": func_name,
                "kind": "func",
                "description": doc.get(func_name, ""),
                "references": refs,
                "calls": calls,
            })

    # --- package-level vars ---
    for m in re.finditer(r'^var\s+(\w+)', clean, re.MULTILINE):
        name = m.group(1)
        objects.append({"name": name, "kind": "var",
                        "description": doc.get(name, ""), "references": []})

    # --- package-level consts ---
    for m in re.finditer(r'^const\s+(\w+)\b', clean, re.MULTILINE):
        name = m.group(1)
        objects.append({"name": name, "kind": "const",
                        "description": doc.get(name, ""), "references": []})

    return objects


# ---------------------------------------------------------------------------
# Main generator
# ---------------------------------------------------------------------------

def generate(go_file: Path) -> dict:
    source = go_file.read_text(encoding="utf-8")

    pkg_m = re.search(r'^\s*package\s+(\w+)', source, re.MULTILINE)
    package = pkg_m.group(1) if pkg_m else ""

    module_name = _find_module_name(go_file)
    imports = _parse_imports(source)
    objects = _parse_objects(source, imports, module_name)

    return {
        "package": package,
        "description": _extract_package_doc(source),
        "tags": _suggest_tags(go_file, imports, objects),
        "category": [],
        "used_in": [],
        "entrypoint": package == "main",
        "related_nodes": [],
        "objects": objects,
    }


def _detect_implements(yaml_dir: Path) -> dict[str, list[str]]:
    """Scan all YAML files in yaml_dir and return {struct_name: [interface_names]}
    based on method-set inclusion.

    A struct S implements interface I if all exported methods of I appear as
    kind=method objects with receiver=S across any YAML in the directory.

    Returns a dict mapping struct names to the list of interfaces they implement.
    Does NOT modify any files — callers are responsible for applying results.
    """
    ifaces: dict[str, set[str]] = {}   # {iface_name: {method_name, ...}}
    struct_methods: dict[str, set[str]] = {}  # {struct_name: {method_name, ...}}

    for yaml_file in sorted(yaml_dir.glob("*.yaml")):
        try:
            with open(yaml_file) as f:
                data = yaml.safe_load(f) or {}
        except Exception:
            continue
        for obj in data.get("objects", []):
            kind = obj.get("kind")
            name = obj.get("name", "")
            if kind == "interface":
                methods = obj.get("methods", [])
                if methods:
                    ifaces[name] = set(methods)
            elif kind == "method":
                receiver = obj.get("receiver", "")
                if receiver:
                    struct_methods.setdefault(receiver, set()).add(name)

    result: dict[str, list[str]] = {}
    for struct, methods in struct_methods.items():
        impls = []
        for iface, iface_methods in ifaces.items():
            if iface_methods and iface_methods.issubset(methods):
                impls.append(iface)
        if impls:
            result[struct] = sorted(impls)
    return result


def _merge_data(new_data: dict, old_data: dict) -> dict:
    """Merge freshly generated data into an existing YAML.

    Auto fields (always updated from source):
      package, entrypoint, objects.references, objects.kind, objects.receiver

    Description fields (updated only if doc comment exists in source):
      description (file-level), objects[].description
      If the new description is empty, the existing value is preserved.

    Manual fields (never touched):
      tags, category, used_in, related_nodes, objects[].implements

    Objects:
      - New objects (added to Go source) → appended
      - Removed objects (deleted from Go source) → dropped
      - Existing objects → merged per field rules above
    """
    merged = dict(new_data)

    # preserve all manual top-level fields
    merged['tags'] = old_data.get('tags', new_data.get('tags', []))
    merged['category'] = old_data.get('category', [])
    merged['used_in'] = old_data.get('used_in', [])
    merged['related_nodes'] = old_data.get('related_nodes', [])

    # description: keep new if non-empty (from doc comment), else preserve old
    if not merged.get('description'):
        merged['description'] = old_data.get('description', '')

    # merge objects by name
    old_by_name: dict[str, dict] = {o['name']: o for o in old_data.get('objects', [])}
    merged_objects = []
    for new_obj in new_data.get('objects', []):
        name = new_obj['name']
        if name in old_by_name:
            old_obj = old_by_name[name]
            obj = dict(new_obj)                          # structural fields from new
            if obj.get('kind') == 'struct':              # implements only meaningful on structs
                obj['implements'] = old_obj.get('implements', [])
            if not obj.get('description'):               # keep manual description if no doc comment
                obj['description'] = old_obj.get('description', '')
        else:
            obj = new_obj                                # new object — use as-is
        merged_objects.append(obj)

    merged['objects'] = merged_objects
    return merged


def _write_yaml(data: dict, path: Path) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write("---\n")
        yaml.dump(data, f, allow_unicode=True, default_flow_style=False,
                  sort_keys=False)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate companion YAML skeletons for Go source files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("files", nargs="*", metavar="FILE",
                        help="Go source files to process")
    parser.add_argument("--dir", metavar="DIR",
                        help="Process all .go files in DIR")
    parser.add_argument("--recursive", action="store_true",
                        help="Recurse into subdirectories (use with --dir)")
    parser.add_argument("--overwrite", action="store_true",
                        help="Overwrite existing YAML files completely")
    parser.add_argument("--merge", action="store_true",
                        help="Update auto fields (references, descriptions from doc comments) "
                             "while preserving manual fields (tags, category, used_in, "
                             "related_nodes, implements). Implies --overwrite for existing files.")
    parser.add_argument("--skip-tests", action="store_true",
                        help="Skip _test.go files")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print actions without writing files")
    parser.add_argument("--detect-implements", action="store_true",
                        help="After generating/merging, detect interface implementations "
                             "by method-set inclusion across all YAMLs in the same directory "
                             "and fill in the implements field. Only effective with --dir.")
    args = parser.parse_args()

    files: list[Path] = [Path(f) for f in args.files]
    dirs_processed: set[Path] = set()
    if args.dir:
        d = Path(args.dir)
        glob = d.rglob("*.go") if args.recursive else d.glob("*.go")
        files += list(glob)

    if not files:
        parser.print_help()
        sys.exit(1)

    generated = merged_count = skipped = errors = 0
    for go_file in sorted(set(files)):
        if not go_file.exists():
            print(f"NOT FOUND: {go_file}", file=sys.stderr)
            errors += 1
            continue
        if args.skip_tests and go_file.name.endswith("_test.go"):
            continue

        yaml_file = go_file.with_suffix(".yaml")
        existing = yaml_file.exists()

        if existing and not args.overwrite and not args.merge:
            print(f"SKIP (exists): {yaml_file}")
            skipped += 1
            continue

        try:
            data = generate(go_file)
        except Exception as e:
            print(f"ERROR: {go_file}: {e}", file=sys.stderr)
            errors += 1
            continue

        if existing and args.merge:
            try:
                with open(yaml_file) as f:
                    old_data = yaml.safe_load(f) or {}
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
            dirs_processed.add(go_file.parent)

    summary = f"\nDone: {generated} generated, {merged_count} merged, {skipped} skipped, {errors} errors"
    print(summary)

    # Interface implementation detection pass
    if args.detect_implements and not args.dry_run and dirs_processed:
        impl_count = 0
        for yaml_dir in sorted(dirs_processed):
            impl_map = _detect_implements(yaml_dir)
            if not impl_map:
                continue
            for yaml_file in sorted(yaml_dir.glob("*.yaml")):
                try:
                    with open(yaml_file) as f:
                        data = yaml.safe_load(f) or {}
                except Exception:
                    continue
                changed = False
                for obj in data.get("objects", []):
                    if obj.get("kind") == "struct":
                        impls = impl_map.get(obj["name"], [])
                        if impls and obj.get("implements") != impls:
                            obj["implements"] = impls
                            changed = True
                            impl_count += 1
                if changed:
                    _write_yaml(data, yaml_file)
                    print(f"IMPLEMENTS: {yaml_file.name} — updated {sum(1 for o in data['objects'] if o.get('kind')=='struct' and o.get('implements'))} structs")
        print(f"Interface detection: {impl_count} struct(s) updated with implements")

    if errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
