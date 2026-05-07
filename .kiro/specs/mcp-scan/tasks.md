# Implementation Plan: mcp-scan

## Overview

Implement mcp-scan as a Python library and CLI tool for detecting security vulnerabilities in MCP servers. The implementation proceeds bottom-up: data models and package scaffolding first, then the taint tracker and static analyzer core, then the 12 detection rules (MCP001–005, MCP010–014, MCP020–021), then the dynamic prober, then output formatters, and finally the CLI and packaging. Each layer is tested before the next is built on top of it.

## Tasks

- [x] 1. Set up package structure and core data models
  - Create `pyproject.toml` with `uv`, Python ≥ 3.11, and lower-bounded runtime dependencies (`mcp`, `httpx`, `pydantic`, `rich`, `typer`, `hypothesis`, `pytest`, `pytest-cov`); commit `uv.lock` for reproducible dev environments
  - Create the full `mcp_scan/` directory tree with all `__init__.py` stubs
  - Implement `mcp_scan/models.py`: `Severity` enum, `Finding` (with `confidence: Literal["HIGH", "LOW"] = "HIGH"`), `ScanResult`, `ScanConfig`, and `RuleMetadata` dataclass
  - Export `Scanner`, `Finding`, `ScanResult`, `Severity` from `mcp_scan/__init__.py`
  - _Requirements: 1.1, 1.2, 1.3, 1.5, 14.1, 14.2, 14.3_

  - [x] 1.1 Write property test for ScanResult JSON round-trip
    - **Property 1: ScanResult JSON round-trip**
    - Use Hypothesis to generate arbitrary `ScanResult` objects (varying findings count, severity values, scan mode, target, timestamp) and assert `model_validate_json(result.model_dump_json()) == result`
    - Tag: `# Feature: mcp-scan, Property 1: ScanResult JSON round-trip`
    - **Validates: Requirements 1.4, 9.7, 13.6**

  - [x] 1.2 Write unit tests for models
    - Test `Severity` enum values and ordering
    - Test `Finding` field validation and defaults (including `confidence="HIGH"` default)
    - Test `ScanResult` serialization/deserialization round-trip with fixed examples
    - _Requirements: 1.1, 1.2, 1.3, 1.4_

- [x] 2. Implement the Rule ABC and auto-discovery
  - Implement `mcp_scan/rules/__init__.py`: `Rule` ABC with `rule_id`, `severity`, `cwe`, `description`, `remediation` class attributes and abstract `check(tree, source_path) -> list[Finding]` method
  - Implement auto-discovery: scan `mcp_scan.rules` submodules for all concrete `Rule` subclasses; return them sorted by `rule_id`
  - _Requirements: 2.6, 2.7_

  - [x] 2.1 Write unit tests for Rule ABC and auto-discovery
    - Test that a concrete stub rule is discovered automatically without manual registration
    - Test that the returned list is sorted by `rule_id`
    - _Requirements: 2.6, 2.7_

- [x] 3. Implement the TaintTracker
  - Implement `mcp_scan/static/taint.py`: `TaintTracker(ast.NodeVisitor)` with `__init__(tainted_params)`, `is_tainted(node)`, `visit_Assign`, `visit_AugAssign`, `visit_AnnAssign`
  - Propagate taint through direct assignment, string concatenation (`ast.BinOp` with `ast.Add`), and f-strings (`ast.JoinedStr`)
  - Implement allowlist detection: clear taint when a value passes through `re.match`/`re.fullmatch`, explicit `in` membership test, `urlparse(...).hostname in ...`, a Pydantic `@field_validator` on the same-file class, or a name in `trusted_validators`
  - Implement `_is_mcp_tool(func_def)` helper: returns `True` if the function has a `@mcp.tool()` or `@server.tool()` decorator
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_

  - [x] 3.1 Write unit tests for TaintTracker
    - Test taint propagation through assignment, f-string, and concatenation
    - Test taint cleared by `re.match`, membership test, `urlparse` hostname check
    - Test Pydantic `@field_validator` sanitization (same-file class only — MVP scope)
    - Test `trusted_validators` config list clears taint
    - _Requirements: 3.2, 3.3, 3.4_

  - [x] 3.2 Write property test for taint sanitization suppression
    - **Property 7: Taint sanitization suppresses findings**
    - Generate Python source files where tainted params are validated before sinks; assert zero findings for MCP001–005
    - Tag: `# Feature: mcp-scan, Property 7: Taint sanitization suppresses findings`
    - **Validates: Requirements 3.4**

- [x] 4. Implement the StaticAnalyzer core
  - Implement `mcp_scan/static/analyzer.py`: `StaticAnalyzer` with `analyze_path(path)` and `analyze_file(path)`
  - File discovery: `sorted(root.rglob("*.py"))` for deterministic ordering; respect `exclude_paths` glob patterns from `ScanConfig`
  - Build per-file alias map from `ast.Import` and `ast.ImportFrom` nodes; cover `from urllib.parse import urlparse` explicitly
  - Parse error handling: emit `Finding(severity=INFO, rule_id="PARSE_ERROR", ...)` and continue
  - Rule dispatch: apply rules in ascending `rule_id` order (sort auto-discovered list before dispatch)
  - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.8_

  - [x] 4.1 Write unit tests for StaticAnalyzer
    - Test recursive `.py` file discovery from a directory
    - Test parse error produces INFO finding and continues
    - Test alias map: `from urllib.parse import urlparse` → `{"urlparse": ("urllib.parse", "urlparse")}` (dedicated regression test)
    - Test alias map: `from httpx import get as fetch` and `import httpx as h`
    - Test rule dispatch order is stable (sorted by `rule_id`)
    - _Requirements: 2.2, 2.3, 2.4, 2.8_

  - [x] 4.2 Write property test for static analysis determinism
    - **Property 2: Static analysis determinism**
    - Generate arbitrary valid Python source strings; run `StaticAnalyzer` twice and assert identical `Finding` lists
    - Tag: `# Feature: mcp-scan, Property 2: Static analysis determinism`
    - **Validates: Requirements 2.8**

  - [x] 4.3 Write property test for all rules applied to every file
    - **Property 8: All rules are applied to every analyzed file**
    - For N registered rules and any source file, assert `check()` is called exactly once per rule per file
    - Tag: `# Feature: mcp-scan, Property 8: All rules are applied to every analyzed file`
    - **Validates: Requirements 2.5**

- [x] 5. Checkpoint — core infrastructure complete
  - Ensure all tests pass, ask the user if questions arise.

- [x] 6. Implement SSRF and request-side rules (MCP001–005)
  - Create `mcp_scan/rules/ssrf.py` with five `Rule` subclasses
  - MCP001: `httpx`/`requests` HTTP calls where URL arg is tainted (HIGH, CWE-918); use alias map for aliased imports
  - MCP002: any HTTP client call missing `timeout=` kwarg (LOW)
  - MCP003: `urllib.request.urlopen` where URL arg is tainted (HIGH, CWE-918)
  - MCP004: `subprocess.run/call/Popen` with `shell=True` and tainted arg (CRITICAL, CWE-78)
  - MCP005: `open()` where path arg is tainted (HIGH, CWE-22)
  - Create `tests/fixtures/` positive and negative fixture `.py` files for each rule
  - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6_

  - [x] 6.1 Write unit tests for MCP001–005 (positive and negative cases)
    - One positive fixture (vulnerable pattern) and one negative fixture (clean pattern) per rule
    - Test aliased import detection for MCP001 (e.g., `from httpx import get as fetch`)
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 13.1, 13.2_

  - [x] 6.2 Write property test for SSRF rules — no false positives on clean files
    - **Property 3: SSRF rules produce no false positives on clean files**
    - Generate Python files with MCP tool handlers using HTTP clients with only literal URLs; assert zero findings for MCP001–005
    - Tag: `# Feature: mcp-scan, Property 3: SSRF rules produce no false positives on clean files`
    - **Validates: Requirements 4.6**

- [x] 7. Implement secrets and auth misconfiguration rules (MCP010–014)
  - Create `mcp_scan/rules/secrets.py` with five `Rule` subclasses
  - MCP010: string literal assigned to `api_key`/`apikey`/`token`/`secret`-named variable (CRITICAL)
  - MCP011: string literal assigned to `password`/`passwd`-named variable (CRITICAL)
  - MCP012: `http://` string literal in auth/API context (MEDIUM)
  - MCP013: OAuth URL construction without `code_challenge` parameter (HIGH)
  - MCP014: tainted credential variable passed to `print()` or logging function (HIGH); reuse `TaintTracker`
  - Create positive and negative fixture `.py` files for each rule
  - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6_

  - [x] 7.1 Write unit tests for MCP010–014 (positive and negative cases)
    - One positive and one negative fixture per rule
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 13.1, 13.2_

  - [x] 7.2 Write property test for secrets rules — no false positives on clean files
    - **Property 4: Secrets rules produce no false positives on clean files**
    - Generate Python files with no credential-named variables and no `http://` auth URLs; assert zero findings for MCP010–014
    - Tag: `# Feature: mcp-scan, Property 4: Secrets rules produce no false positives on clean files`
    - **Validates: Requirements 5.6**

- [x] 8. Implement tool description and prompt injection rules (MCP020–021)
  - Create `mcp_scan/rules/injection.py` with two `Rule` subclasses
  - MCP020: tool description contains Unicode code points > U+00FF (HIGH); extract description from docstring and `description=` kwarg in `@mcp.tool()` decorator
  - MCP021: tool description matches `INJECTION_PATTERN` regex (HIGH)
  - Create positive and negative fixture `.py` files for each rule
  - _Requirements: 6.1, 6.2, 6.5_

  - [x] 8.1 Write unit tests for MCP020–021 (positive and negative cases)
    - One positive and one negative fixture per rule
    - Test description extraction from both docstring and `description=` kwarg
    - _Requirements: 6.1, 6.2, 13.1, 13.2_

  - [x] 8.2 Write property test for tool description rules — no false positives on clean descriptions
    - **Property 5: Tool description rules produce no false positives on clean descriptions**
    - Generate tool description strings with only code points ≤ U+00FF and no injection phrases; assert zero findings for MCP020–021
    - Tag: `# Feature: mcp-scan, Property 5: Tool description rules produce no false positives on clean descriptions`
    - **Validates: Requirements 6.5**

- [x] 9. Checkpoint — all 12 static rules complete
  - Ensure all tests pass, ask the user if questions arise.

- [x] 10. Implement the DynamicProber
  - Implement `mcp_scan/dynamic/probes.py`: `SSRF_PROBES`, `INJECTION_PROBES`, `AUTH_PROBES` payload lists; `DESTRUCTIVE_PATTERNS` regex
  - Implement `mcp_scan/dynamic/prober.py`: `DynamicProber(timeout=30, allow_destructive=False)`
    - `_connect_stdio(command)`: use `mcp.client.stdio.stdio_client` with `StdioServerParameters`
    - `_connect_http(url)`: use `mcp.client.streamable_http.streamablehttp_client`
    - `_enumerate_tools(session)`: call `session.list_tools()`, extract name/description/inputSchema
    - `_is_destructive_tool(tool_name)`: match against `DESTRUCTIVE_PATTERNS`
    - `_run_probes(session, tools)`: dispatch probes to string-typed params; skip destructive tools unless `allow_destructive=True`; apply MCP020/021 description analysis to all tools
    - SSRF findings without `--ssrf-listener`: emit `confidence="LOW"` finding
    - `probe(target)`: top-level coroutine; use `async with` for transport and session; catch connection errors and emit INFO finding
  - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 8.1, 8.2, 8.3, 8.4, 8.5, 8.6_

  - [x] 10.1 Write unit tests for DynamicProber
    - Mock `ClientSession` to test tool enumeration and probe dispatch
    - Test destructive tool skipping when `allow_destructive=False`
    - Test destructive tool probing when `allow_destructive=True`
    - Test connection failure emits INFO finding and returns partial `ScanResult`
    - Test SSRF finding without `--ssrf-listener` has `confidence="LOW"`
    - Test `asyncio.run()` integration pattern for CLI entry point
    - _Requirements: 7.3, 7.4, 7.5, 7.6, 8.1, 8.4_

- [x] 11. Create sample vulnerable MCP server fixture
  - Create `tests/fixtures/servers/vulnerable_server.py`: an MCP server exposing tools with an SSRF vulnerability (tainted URL to `httpx.get`), a hardcoded secret (`api_key = "sk-..."`), and a prompt-injection tool description
  - _Requirements: 13.3_

- [x] 12. Implement the Scanner facade
  - Implement `mcp_scan/scanner.py`: `Scanner(config=None)` with `scan_static(path)`, `scan_dynamic(target)`, `scan_all(path, target)`
  - `scan_all` merges findings from both analyzers into a single `ScanResult` with `scan_mode="all"`
  - Apply `ScanConfig` filters (disabled rules, min severity, exclude paths) in the facade
  - _Requirements: 10.3_

  - [x] 12.1 Write unit tests for Scanner facade
    - Test `scan_static` delegates to `StaticAnalyzer` and returns `ScanResult`
    - Test `scan_all` merges findings from both analyzers
    - Test disabled rules are not executed
    - Test min severity filter is applied
    - _Requirements: 10.3, 11.2, 11.3_

- [x] 13. Implement output formatters
  - Implement `mcp_scan/formatters/rich_formatter.py`: render `rich.table.Table` with severity color mapping; success message when no findings
  - Implement `mcp_scan/formatters/json_formatter.py`: return `result.model_dump_json(indent=2)`
  - Implement `mcp_scan/formatters/sarif_formatter.py`: build SARIF 2.1.0 document with severity→level mapping (CRITICAL/HIGH→`"error"`, MEDIUM→`"warning"`, LOW/INFO→`"note"`)
  - Implement `mcp_scan/formatters/markdown_formatter.py`: summary table + per-finding `###` sections
  - Create `tests/snapshots/` directory and reference snapshot files for each formatter
  - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.6_

  - [x] 13.1 Write snapshot tests for all formatters
    - Render a fixed `ScanResult` with each formatter and compare against stored reference in `tests/snapshots/`
    - Include a zero-findings case for each formatter
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.6, 13.5_

- [x] 14. Checkpoint — formatters and scanner facade complete
  - Ensure all tests pass, ask the user if questions arise.

- [x] 15. Implement the CLI
  - Implement `mcp_scan/cli.py` using `typer`
  - `static` subcommand: `--path`, `--format`, `--output`, `--severity`, `--rule`, `--config`; call `scanner.scan_static(path)`
  - `dynamic` subcommand: `--target`, `--format`, `--output`, `--severity`, `--config`, `--allow-destructive`, `--yes`, `--ssrf-listener`; run `asyncio.run(scanner.scan_dynamic(target))`
  - `all` subcommand: `--path`, `--target`, plus all shared flags; run `asyncio.run(scanner.scan_all(path, target))`
  - `rules` subcommand: list all registered rules with ID, severity, description, CWE
  - `--allow-destructive` confirmation prompt (skippable with `--yes`/`-y`)
  - Exit codes: 0 (no HIGH+ findings), 1 (HIGH+ findings found), 2 (runtime/config error)
  - `--version` flag
  - Wire formatter selection based on `--format` flag; write to file when `--output` is provided
  - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7, 10.8, 10.9, 10.10_

  - [x] 15.1 Write CLI tests using `typer.testing.CliRunner`
    - Test each subcommand with valid and invalid arguments
    - Test `--severity` filter reduces output
    - Test `--rule` flag runs only the specified rule
    - Test `--config` flag loads configuration file
    - Test exit code 0 for no HIGH+ findings, exit code 1 for HIGH+ findings, exit code 2 for config error
    - Test `--version` prints version and exits 0
    - Test `--allow-destructive` shows confirmation prompt; `--yes` skips it
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7, 10.8, 10.9, 10.10_

- [x] 16. Implement configuration file loading
  - Implement `mcp_scan/config.py`: load `ScanConfig` from TOML (via `tomllib`) or JSON; validate with Pydantic; warn on unrecognized keys; CLI flags override config values
  - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5_

  - [x] 16.1 Write unit tests for config loading
    - Test valid TOML and JSON loading
    - Test malformed file exits with code 2 and error message
    - Test unrecognized keys emit warning but continue
    - Test CLI flag overrides config file value
    - _Requirements: 11.1, 11.4, 11.5_

- [x] 17. Implement severity filter and property test
  - Implement severity filtering in `Scanner` (or `StaticAnalyzer`): given `min_severity`, return only findings at or above that level
  - _Requirements: 10.5_

  - [x] 17.1 Write property test for severity filter monotonicity
    - **Property 6: Severity filter monotonicity**
    - Generate `ScanResult` objects with mixed severities; for any S1 < S2, assert `filter(result, S1) ⊇ filter(result, S2)`
    - Tag: `# Feature: mcp-scan, Property 6: Severity filter monotonicity`
    - **Validates: Requirements 10.5**

- [x] 18. Create GitHub Action
  - Create `.github/actions/mcp-scan/action.yml` as a composite action
  - Inputs: `path`, `severity`, `format`, `args`
  - Steps: install mcp-scan via `pip`, run `mcp-scan static`, upload artifact when format is `sarif` or `json`
  - Set step outcome to failure when exit code is 1
  - _Requirements: 12.1, 12.2, 12.3, 12.4, 12.5_

- [x] 19. Final checkpoint — full test suite and coverage
  - Run `pytest --cov=mcp_scan --cov-fail-under=80` and ensure ≥ 80% line coverage
  - Ensure all snapshot tests pass
  - Ensure all property-based tests pass (minimum 100 iterations each)
  - Ensure all positive and negative rule fixture tests pass
  - Ensure all tests pass, ask the user if questions arise.
  - _Requirements: 13.4_

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP delivery
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation at each major layer boundary
- Property tests validate universal correctness properties (Properties 1–8 from the design)
- Unit tests validate specific examples, edge cases, and error conditions
- MCP022 and MCP023 are explicitly deferred — do not implement them
- Dynamic SSRF findings without `--ssrf-listener` must always use `confidence="LOW"`
- The `from urllib.parse import urlparse` alias map case has a dedicated regression test (task 4.1)
- Pydantic `@field_validator` taint sanitization is scoped to same-file class definitions only (MVP)
- All async CLI entry points use `asyncio.run()` since typer does not natively support async
