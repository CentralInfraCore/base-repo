{
  "mcpServers": {
    "cic-graph": {
      "command": "{{REPO_ROOT}}/p_venv/bin/python",
      "args": [
        "{{REPO_ROOT}}/mcp-server/server.py"
      ],
      "env": {
        "KB_DATA_DIR": "{{REPO_ROOT}}/kb_data/pkl"
      }
    }
  }
}
