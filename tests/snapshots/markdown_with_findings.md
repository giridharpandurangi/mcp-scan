# mcp-bandit Security Report

**Target:** `src/server.py`
**Scan mode:** static
**Timestamp:** 2024-01-15T12:00:00+00:00
**Tool version:** 0.1.0

## Summary (3 finding(s))

| Rule ID | Severity | Location | Message |
|---------|----------|----------|---------|
| MCP001 | HIGH | `src/server.py:42` | Tainted URL passed to HTTP client — potential SSRF. Sink: httpx.get |
| MCP010 | CRITICAL | `src/server.py:10` | Hardcoded API key assigned to variable api_key. |
| MCP021 | HIGH | `src/server.py:5` | Tool description contains prompt injection phrase: ignore previous instructions |

## Findings

### 1. [MCP001] HIGH — src/server.py:42

**Message:** Tainted URL passed to HTTP client — potential SSRF. Sink: httpx.get

**Target:** `src/server.py`

**Remediation:** Validate the URL against an allowlist before passing it to an HTTP client.

### 2. [MCP010] CRITICAL — src/server.py:10

**Message:** Hardcoded API key assigned to variable api_key.

**Target:** `src/server.py`

**Remediation:** Use environment variables or a secrets manager instead of hardcoding credentials.

### 3. [MCP021] HIGH — src/server.py:5

**Message:** Tool description contains prompt injection phrase: ignore previous instructions

**Target:** `src/server.py`

**Remediation:** Remove or rewrite the tool description to avoid injection phrases.
