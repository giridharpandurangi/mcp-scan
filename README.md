# mcp-scan

Security scanner for Model Context Protocol (MCP) servers. Detects vulnerabilities via static AST analysis of Python source code and dynamic probing of live MCP servers.

## Detection Rules

| Rule | Category | Severity | Description |
|------|----------|----------|-------------|
| MCP001 | SSRF | HIGH | Tainted URL passed to `httpx`/`requests` HTTP client |
| MCP002 | SSRF | LOW | HTTP client call missing `timeout` argument |
| MCP003 | SSRF | HIGH | Tainted URL passed to `urllib.request.urlopen` |
| MCP004 | Command Injection | CRITICAL | Tainted argument passed to `subprocess` with `shell=True` |
| MCP005 | Path Traversal | HIGH | Tainted path passed to `open()` |
| MCP010 | Secrets | CRITICAL | Hardcoded API key, token, or secret in source code |
| MCP011 | Secrets | CRITICAL | Hardcoded password in source code |
| MCP012 | Auth | MEDIUM | Insecure `http://` URL used in auth/API context |
| MCP013 | Auth | HIGH | OAuth authorization URL missing PKCE `code_challenge` |
| MCP014 | Secrets | HIGH | Credential variable passed to `print()` or logging |
| MCP020 | Prompt Injection | HIGH | Tool description contains non-Latin-1 Unicode (> U+00FF) |
| MCP021 | Prompt Injection | HIGH | Tool description contains prompt injection phrases |

## Installation

```bash
pip install mcp-scan
# or
uv add mcp-scan
```

Requires Python 3.11+.

## Usage

### Static analysis

Scan a Python source file or directory:

```bash
mcp-scan static --path src/
mcp-scan static --path my_server.py
```

### Dynamic probing

Connect to a running MCP server and send crafted probe inputs:

```bash
# stdio transport (command string)
mcp-scan dynamic --target "python my_server.py"

# HTTP transport
mcp-scan dynamic --target "http://localhost:8080"
```

> **Warning**: Dynamic probing sends crafted inputs to live MCP tools. Always run against a development or staging server, never production.

### Both modes combined

```bash
mcp-scan all --path src/ --target "python my_server.py"
```

### List all rules

```bash
mcp-scan rules
```

## CLI Options

### Shared flags

| Flag | Description |
|------|-------------|
| `--format` / `-f` | Output format: `rich` (default), `json`, `sarif`, `markdown` |
| `--output` / `-o` | Write output to a file instead of stdout |
| `--severity` / `-s` | Minimum severity to report: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` |
| `--rule` / `-r` | Run only a specific rule (e.g. `MCP001`) |
| `--config` / `-c` | Path to a TOML or JSON configuration file |

### Dynamic-only flags

| Flag | Description |
|------|-------------|
| `--allow-destructive` | Send probes to tools with destructive names (`delete*`, `drop*`, `write*`, etc.) |
| `--yes` / `-y` | Skip the `--allow-destructive` confirmation prompt |
| `--ssrf-listener` | Address of a controlled HTTP listener for confirmed SSRF detection |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed, no findings at or above HIGH severity |
| `1` | Scan completed, one or more HIGH+ findings found |
| `2` | Scan failed due to configuration or runtime error |

## Output Formats

```bash
# Rich terminal table (default)
mcp-scan static --path src/

# JSON (ScanResult schema)
mcp-scan static --path src/ --format json

# SARIF 2.1.0 (for GitHub Code Scanning)
mcp-scan static --path src/ --format sarif --output results.sarif

# Markdown report
mcp-scan static --path src/ --format markdown --output report.md
```

## Configuration File

Create a `mcp-scan.toml` (or `.json`) file to set persistent options:

```toml
# mcp-scan.toml
disabled_rules = ["MCP002"]
exclude_paths = ["tests/**", "docs/**"]
min_severity = "MEDIUM"
output_format = "rich"
trusted_validators = ["validate_url", "is_safe_path"]
```

Or embed it in `pyproject.toml`:

```toml
[tool.mcp-scan]
disabled_rules = ["MCP002"]
min_severity = "HIGH"
```

Load it with:

```bash
mcp-scan static --path src/ --config mcp-scan.toml
```

CLI flags always override config file values.

### `trusted_validators`

The taint tracker is intra-procedural — it can't follow calls into helper functions. If you have a custom sanitizer (e.g. `validate_url(x)`), register its name to suppress false positives:

```toml
trusted_validators = ["validate_url", "is_safe_path", "check_host"]
```

## GitHub Action

Add mcp-scan to your CI pipeline:

```yaml
# .github/workflows/security.yml
- name: Run mcp-scan
  uses: ./.github/actions/mcp-scan
  with:
    path: src/
    severity: HIGH
    format: sarif
```

The action uploads SARIF output as a workflow artifact and fails the step when HIGH+ findings are found.

## Python API

```python
from mcp_scan import Scanner, Finding, ScanResult, Severity

scanner = Scanner()

# Static analysis
result: ScanResult = scanner.scan_static("src/")

# Dynamic probing
import asyncio
result = asyncio.run(scanner.scan_dynamic("python my_server.py"))

# Filter findings
high_plus = [f for f in result.findings if f.severity >= Severity.HIGH]
```

### Configuration via API

```python
from mcp_scan.models import ScanConfig

config = ScanConfig(
    disabled_rules=["MCP002"],
    min_severity=Severity.MEDIUM,
    exclude_paths=["tests/**"],
    trusted_validators=["validate_url"],
)
scanner = Scanner(config=config)
```

## Development

```bash
# Install with dev dependencies
uv sync --extra dev

# Run tests
pytest

# Run tests with coverage
pytest --cov=mcp_scan --cov-fail-under=80

# Run a specific test file
pytest tests/test_rules_ssrf.py -v
```

The test suite includes unit tests, snapshot tests for all formatters, and property-based tests (via [Hypothesis](https://hypothesis.readthedocs.io/)) covering:

- ScanResult JSON round-trip fidelity
- Static analysis determinism
- No false positives on clean files (SSRF, secrets, injection rules)
- Severity filter monotonicity
- All rules applied to every analyzed file
- Taint sanitization suppresses findings
