#!/usr/bin/env python3
"""
CIC Agent Orchestrator

Deterministic, zero-token agent runner built on PROMPTMAP.yaml task queue.

Flow:
  1. Parse PROMPTMAP → pick next todo task (highest priority)
  2. Load task profile (task_profile field) + scope profile (scope_profile field)
  3. Build agent briefing from profiles + task prompt
  4. Print briefing to stdout (agent reads it) or spawn subprocess
  5. Run accept gate (accept field from task)
  6. On exit 0 → mark task done; on fail → mark task failed (max retries)

Usage:
  python orchestrator.py --repo CIC-Relay --sprint 15
  python orchestrator.py --repo CIC-Relay --task upstream-source-http --print-briefing
  python orchestrator.py --list-tasks --repo CIC-Relay --status todo
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional

import yaml

# --- Configuration ---

PROFILES_BASE = Path(__file__).parent.parent / "ai" / "profiles"
TASK_PROFILES_DIR = PROFILES_BASE / "task"
SCOPE_PROFILES_DIR = PROFILES_BASE / "scope"

# Colon-separated list of PROMPTMAP.yaml paths; if unset, scanned from SOURCE_DIR.
PROMPTMAP_PATHS_ENV = os.environ.get("PROMPTMAP_PATHS", "")
SOURCE_DIR = Path(os.environ.get("SOURCE_DIR", str(Path(__file__).parent.parent / "source")))

MAX_RETRIES = int(os.environ.get("ORCHESTRATOR_MAX_RETRIES", "2"))


# --- PROMPTMAP helpers ---

def find_promptmaps() -> list[Path]:
    if PROMPTMAP_PATHS_ENV:
        return [Path(p) for p in PROMPTMAP_PATHS_ENV.split(":") if p.strip()]
    return list(SOURCE_DIR.rglob("PROMPTMAP.yaml"))


def _repo_name(path: Path) -> str:
    parts = path.parts
    try:
        idx = list(parts).index("ai")
        return parts[idx - 1] if idx > 0 else path.parent.parent.name
    except ValueError:
        return path.parent.parent.name


def iter_tasks(data: dict, sprint: Optional[int] = None):
    """Yield (sprint_num, task_dict) from a PROMPTMAP structure."""
    for entry in data.get("entries", []):
        if isinstance(entry, dict):
            yield None, entry
    for block in data.get("sprints", []):
        snum = block.get("sprint")
        for task in block.get("tasks", []):
            if sprint is None or snum == sprint:
                yield snum, task
    if "sprint" in data and "tasks" in data:
        snum = data["sprint"]
        for task in data["tasks"]:
            if sprint is None or snum == sprint:
                yield snum, task


def load_tasks(repo: str = "", sprint: Optional[int] = None, status: Optional[str] = None) -> list[dict]:
    results = []
    for pm_path in find_promptmaps():
        rname = _repo_name(pm_path)
        if repo and repo.lower() not in rname.lower():
            continue
        with pm_path.open() as f:
            data = yaml.safe_load(f) or {}
        for snum, task in iter_tasks(data, sprint):
            if not isinstance(task, dict):
                continue
            if status and task.get("status") != status:
                continue
            results.append({"repo": rname, "sprint": snum, "pm_path": str(pm_path), **task})
    results.sort(key=lambda x: (x.get("priority") is None, x.get("priority") or 0))
    return results


def update_task_status(pm_path: Path, task_id: str, new_status: str, extra: Optional[dict] = None) -> bool:
    with pm_path.open() as f:
        data = yaml.safe_load(f) or {}
    found = False

    def patch(task: dict) -> None:
        nonlocal found
        if task.get("task") == task_id:
            task["status"] = new_status
            if extra:
                task.update(extra)
            found = True

    for entry in data.get("entries", []):
        if isinstance(entry, dict):
            patch(entry)
    for block in data.get("sprints", []):
        for task in block.get("tasks", []):
            if isinstance(task, dict):
                patch(task)
    if "tasks" in data:
        for task in data["tasks"]:
            if isinstance(task, dict):
                patch(task)

    if found:
        with pm_path.open("w") as f:
            yaml.dump(data, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
    return found


# --- Profile helpers ---

def load_profile(profiles_dir: Path, name: str) -> dict:
    p = profiles_dir / f"{name}.yaml"
    if not p.exists():
        return {}
    with p.open() as f:
        return yaml.safe_load(f) or {}


# --- Briefing builder ---

def build_briefing(task: dict, task_profile: dict, scope_profile: dict) -> str:
    lines = ["# CIC Agent Briefing", ""]
    lines += [f"**Repo**: {task.get('repo', '?')}"]
    lines += [f"**Sprint**: {task.get('sprint', '?')}  |  **Task**: {task.get('task', '?')}  |  **Priority**: {task.get('priority', '?')}"]
    if task.get("milestone"):
        lines += [f"**Milestone**: {task['milestone']}"]
    lines += [""]

    if task_profile:
        lines += ["## Task Profile: " + task_profile.get("profile", "?"), ""]
        lines += [task_profile.get("description", "").strip(), ""]
        if task_profile.get("boot_sequence"):
            lines += ["### Boot sequence"]
            for step in task_profile["boot_sequence"]:
                lines += [f"  - {step}"]
            lines += [""]
        if task_profile.get("forbidden"):
            lines += ["### Forbidden"]
            for item in task_profile["forbidden"]:
                lines += [f"  - {item}"]
            lines += [""]

    if scope_profile:
        lines += ["## Scope Profile: " + scope_profile.get("scope", "?"), ""]
        lines += [scope_profile.get("description", "").strip(), ""]
        if scope_profile.get("owns"):
            lines += ["**Owns**: " + ", ".join(scope_profile["owns"])]
        if scope_profile.get("reads"):
            lines += ["**Reads**: " + ", ".join(scope_profile["reads"])]
        if scope_profile.get("test_cmd"):
            lines += ["**Test cmd**: `" + scope_profile["test_cmd"] + "`"]
        if scope_profile.get("coverage_min"):
            lines += [f"**Coverage min**: {scope_profile['coverage_min']}%"]
        if scope_profile.get("invariants"):
            lines += ["", "### Scope invariants"]
            for inv in scope_profile["invariants"]:
                lines += [f"  - {inv}"]
        if scope_profile.get("mcp_focus_queries"):
            lines += ["", "### MCP focus queries (run these first)"]
            for q in scope_profile["mcp_focus_queries"]:
                lines += [f"  - `focus_pack(\"{q}\")`"]
        lines += [""]

    lines += ["## Task Prompt", ""]
    lines += [task.get("prompt", "").strip(), ""]

    if task.get("tests"):
        lines += ["## Tests to touch"]
        for t in task["tests"]:
            lines += [f"  - {t}"]
        lines += [""]

    if task.get("accept"):
        lines += ["## Accept gate", ""]
        lines += [f"```bash", task.get("accept", "").strip(), "```", ""]

    return "\n".join(lines)


# --- Accept gate runner ---

def run_accept_gate(accept_cmd: str, cwd: Optional[str] = None) -> int:
    print(f"\n[orchestrator] Running accept gate: {accept_cmd}", file=sys.stderr)
    result = subprocess.run(accept_cmd, shell=True, cwd=cwd)
    return result.returncode


# --- Main ---

def main() -> None:
    parser = argparse.ArgumentParser(description="CIC Agent Orchestrator")
    parser.add_argument("--repo", default="", help="Filter by repo name substring")
    parser.add_argument("--sprint", type=int, default=None, help="Filter by sprint number")
    parser.add_argument("--task", default="", help="Specific task ID to run")
    parser.add_argument("--status", default="todo", help="Task status filter (default: todo)")
    parser.add_argument("--list-tasks", action="store_true", help="List tasks and exit")
    parser.add_argument("--print-briefing", action="store_true", help="Print briefing and exit (no accept gate)")
    parser.add_argument("--accept-cwd", default="", help="Working directory for accept gate command")
    args = parser.parse_args()

    if args.list_tasks:
        tasks = load_tasks(repo=args.repo, sprint=args.sprint, status=args.status or None)
        for t in tasks:
            print(f"[{t.get('status','?'):12}] pri={t.get('priority','?'):3}  {t.get('repo','?')}  sprint={t.get('sprint','?')}  task={t.get('task','?')}")
        print(f"\n{len(tasks)} task(s)")
        return

    # Select task
    if args.task:
        tasks = load_tasks(repo=args.repo)
        task = next((t for t in tasks if t.get("task") == args.task), None)
        if task is None:
            print(f"[orchestrator] Task not found: {args.task}", file=sys.stderr)
            sys.exit(1)
    else:
        tasks = load_tasks(repo=args.repo, sprint=args.sprint, status="todo")
        if not tasks:
            print("[orchestrator] No todo tasks found.", file=sys.stderr)
            sys.exit(0)
        task = tasks[0]

    task_profile_name = task.get("task_profile", "implement")
    scope_profile_name = task.get("scope_profile", "")

    task_profile = load_profile(TASK_PROFILES_DIR, task_profile_name) if task_profile_name else {}
    scope_profile = load_profile(SCOPE_PROFILES_DIR, scope_profile_name) if scope_profile_name else {}

    briefing = build_briefing(task, task_profile, scope_profile)
    print(briefing)

    if args.print_briefing:
        return

    # Accept gate
    accept_cmd = task.get("accept", "")
    if not accept_cmd:
        print("[orchestrator] No accept gate defined — marking done.", file=sys.stderr)
        update_task_status(Path(task["pm_path"]), task["task"], "done")
        return

    cwd = args.accept_cwd or None
    for attempt in range(1, MAX_RETRIES + 1):
        rc = run_accept_gate(accept_cmd, cwd=cwd)
        if rc == 0:
            update_task_status(Path(task["pm_path"]), task["task"], "done",
                               {"result": f"accept gate passed on attempt {attempt}"})
            print(f"[orchestrator] Task '{task['task']}' DONE.", file=sys.stderr)
            return
        print(f"[orchestrator] Accept gate failed (attempt {attempt}/{MAX_RETRIES})", file=sys.stderr)

    update_task_status(Path(task["pm_path"]), task["task"], "failed",
                       {"failure_reason": f"accept gate failed after {MAX_RETRIES} attempts"})
    print(f"[orchestrator] Task '{task['task']}' FAILED.", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
