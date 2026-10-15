# MCP Server for Knowledge Base

This directory contains the MCP server implementation that exposes the knowledge base to AI assistants.

## Build info (provenance)

Every KB build and update records which commit / tag of each source repository the
data was built from (`kb_build_info.py`):

* `build_info.yaml` next to the pkl files: per source `remote`, `commit`, tag-based
  `describe`, `tag` (when the commit is tagged), `branch`, `dirty` (tracked changes in the
  checked-out tree) and the `metadata.version` of the repository's `project.yaml`.
* One meta chunk, `c_kb_build_info` (type `kb_build_info`, tags `kb-meta`, `build-info`),
  with the same content, so `search_nodes` / `search_query` find it without file access.
* The `build` section of `kb_status` compares the recorded commits with the source trees
  as they are now: `state` per source (`current`, `behind` with `commits_since`, `ahead`,
  `diverged`, `unknown`, `missing`), `stale`, `sources_dirty_now`, and how far each working
  tree is behind its upstream (`behind_upstream`, from local refs only, so read it together
  with `upstream_fetched_at`).

It is written by every path that changes the KB, so it cannot drift from the data:
`make_source.py` (full build, `trigger: build`), `kb_watch.py` (`trigger: watch`) and the
server's bootstrap (`trigger: boot`). The server's own in-process watch only changes the
KB in memory, so it updates the in-memory record (reported as `origin: memory`) and does
not rewrite the file.

A KB built before this existed has no `build_info.yaml`; `kb_status` says so
(`build.available: false`). Rebuild it to start recording.
