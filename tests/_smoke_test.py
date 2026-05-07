"""Smoke test for StaticAnalyzer implementation."""
from mcp_scan.static.analyzer import StaticAnalyzer, _build_alias_map
import ast
import tempfile
import os
import pathlib

# Test alias map building
src = """
import httpx as h
from httpx import get as fetch
from urllib.parse import urlparse
import os
from os.path import join, exists
"""
tree = ast.parse(src)
alias_map = _build_alias_map(tree)
print("Alias map:", alias_map)

assert alias_map.get("h") == ("httpx", "httpx"), f"Expected h -> (httpx, httpx), got {alias_map.get('h')}"
assert alias_map.get("fetch") == ("httpx", "get"), f"Expected fetch -> (httpx, get), got {alias_map.get('fetch')}"
assert alias_map.get("urlparse") == ("urllib.parse", "urlparse"), f"Expected urlparse -> (urllib.parse, urlparse), got {alias_map.get('urlparse')}"
print("All alias map assertions passed!")

# Test StaticAnalyzer instantiation
analyzer = StaticAnalyzer()
print(f"StaticAnalyzer created with {len(analyzer._rules)} rules")

# Test analyze_file with syntax error
with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
    f.write("def broken(:")
    tmp = f.name
findings = analyzer.analyze_file(tmp)
os.unlink(tmp)
print(f"Parse error findings: {findings}")
assert len(findings) == 1
assert findings[0].rule_id == "PARSE_ERROR"
assert findings[0].severity.value == "INFO"
print("Parse error handling works!")

# Test analyze_path on a directory
result = analyzer.analyze_path(pathlib.Path("."))
print(f"analyze_path result: {len(result.findings)} findings, scan_mode={result.scan_mode}")
assert result.scan_mode == "static"
assert result.target == "."
print("All smoke tests passed!")
