# mcp-scan

Security scanner for Model Context Protocol (MCP) servers.

Detects vulnerabilities in MCP servers via static AST analysis and dynamic probing:
- **SSRF and request-side issues** (MCP001–005)
- **Secrets and auth misconfigurations** (MCP010–014)
- **Prompt injection / tool description attacks** (MCP020–021)

## Installation

```bash
pip install mcp-scan
# or
uv add mcp-scan
```

## Usage

```bash
# Static analysis of a Python source tree
mcp-scan static --path src/

# Dynamic probing of a running MCP server
mcp-scan dynamic --target "python my_server.py"

# Both modes combined
mcp-scan all --path src/ --target "python my_server.py"

# List all registered rules
mcp-scan rules
```

## Development

```bash
uv sync --extra dev
pytest
```
