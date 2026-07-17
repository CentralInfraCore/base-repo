#!/usr/bin/env python3
"""generate_gitmodules.py — Render .gitmodules from a declared knowledge.sources.yaml.

knowledge.sources.yaml is the declared desired state: which knowledge sources
exist, what role/visibility they have, and which build profile(s) include them.
.gitmodules is a generated Git-compatibility artifact — never hand-edited.

Usage:
    python tools/generate_gitmodules.py [--sources knowledge.sources.yaml]
        [--profile internal] [--out .gitmodules] [--check] [--dry-run]

Options:
    --sources   Path to the knowledge sources manifest (default: knowledge.sources.yaml)
    --profile   Which profile's includeVisibility to filter by (default: internal)
    --out       Output .gitmodules path (default: .gitmodules)
    --check     Don't write; compare generated content against --out and exit
                non-zero on drift (for CI)
    --dry-run   Print the generated content without writing it
"""

import argparse
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("PyYAML not found. Install with: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

_REQUIRED_SOURCE_FIELDS = ("id", "path", "repo", "role", "visibility")
_GENERATED_HEADER = (
    "# GENERATED FILE - DO NOT EDIT\n"
    "# Source: {sources_file} (profile: {profile})\n"
)


def load_manifest(path: Path) -> dict:
    with path.open(encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a YAML mapping at the top level")
    return data


def validate_manifest(data: dict, path: Path) -> None:
    if data.get("kind") != "KnowledgeSources":
        raise ValueError(f"{path}: kind must be 'KnowledgeSources'")
    profiles = data.get("profiles")
    if not isinstance(profiles, dict) or not profiles:
        raise ValueError(f"{path}: 'profiles' must be a non-empty mapping")
    sources = data.get("sources")
    if not isinstance(sources, list) or not sources:
        raise ValueError(f"{path}: 'sources' must be a non-empty list")

    seen_ids: set[str] = set()
    for i, source in enumerate(sources):
        missing = [field for field in _REQUIRED_SOURCE_FIELDS if not source.get(field)]
        if missing:
            raise ValueError(f"{path}: sources[{i}] missing required field(s): {missing}")
        if source["id"] in seen_ids:
            raise ValueError(f"{path}: duplicate source id '{source['id']}'")
        seen_ids.add(source["id"])


def select_sources(data: dict, profile: str) -> tuple[list[dict], list[dict]]:
    """Return (included, excluded) sources for the given profile."""
    profiles = data["profiles"]
    if profile not in profiles:
        raise ValueError(f"unknown profile '{profile}'. allowed: {sorted(profiles)}")

    include_visibility = set(profiles[profile].get("includeVisibility", []))
    included: list[dict] = []
    excluded: list[dict] = []
    for source in data["sources"]:
        (included if source["visibility"] in include_visibility else excluded).append(source)
    return included, excluded


def render_gitmodules(included: list[dict], sources_file: str, profile: str) -> str:
    lines = [_GENERATED_HEADER.format(sources_file=sources_file, profile=profile)]
    for source in included:
        lines.append(f'[submodule "{source["path"]}"]')
        lines.append(f'\tpath = {source["path"]}')
        lines.append(f'\turl = {source["repo"]}')
        if source.get("branch"):
            lines.append(f'\tbranch = {source["branch"]}')
        lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Render .gitmodules from knowledge.sources.yaml.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--sources", default="knowledge.sources.yaml",
                        help="Path to the knowledge sources manifest")
    parser.add_argument("--profile", default="internal",
                        help="Profile to filter sources by (default: internal)")
    parser.add_argument("--out", default=".gitmodules",
                        help="Output .gitmodules path")
    parser.add_argument("--check", action="store_true",
                        help="Compare against --out and exit non-zero on drift, instead of writing")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print the generated content without writing it")
    args = parser.parse_args()

    sources_path = Path(args.sources)
    if not sources_path.exists():
        print(f"NOT FOUND: {sources_path}", file=sys.stderr)
        sys.exit(1)

    try:
        data = load_manifest(sources_path)
        validate_manifest(data, sources_path)
        included, excluded = select_sources(data, args.profile)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    content = render_gitmodules(included, str(sources_path), args.profile)

    print(f"profile: {args.profile}")
    print(f"included: {len(included)}")
    for s in included:
        print(f"  + {s['id']} ({s['visibility']})")
    if excluded:
        print(f"excluded: {len(excluded)}")
        for s in excluded:
            print(f"  - {s['id']} ({s['visibility']})")

    if args.dry_run:
        print("\n--- generated .gitmodules ---")
        print(content, end="")
        return

    out_path = Path(args.out)

    if args.check:
        existing = out_path.read_text(encoding="utf-8") if out_path.exists() else None
        if existing != content:
            print(f"\nDRIFT: {out_path} does not match generated output from {sources_path}",
                  file=sys.stderr)
            sys.exit(1)
        print(f"\nOK: {out_path} matches {sources_path} (profile: {args.profile})")
        return

    out_path.write_text(content, encoding="utf-8")
    print(f"\nWROTE: {out_path}")


if __name__ == "__main__":
    main()
