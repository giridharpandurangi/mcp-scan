# Requirements Document

## Introduction

mcp-scan is a CLI tool and Python library that scans Model Context Protocol (MCP) servers for security vulnerabilities. It operates in two modes: static analysis (AST-based inspection of Python source code) and dynamic analysis (connecting to a live MCP server, enumerating tools, and probing behavior). The tool targets four vulnerability categories: SSRF and request-side issues, prompt injection sinks, authentication misconfigurations, and malicious tool descriptions. It produces findings in rich terminal output, JSON, SARIF 2.1.0, and Markdown formats, and ships with a GitHub Action wrapper for CI integration.

---

## Glossary

- **MCP**: Model Context Protocol — the open protocol defined by Anthropic for connecting LLM applications to external tools and data sources.
- **MCP_Server**: A process that exposes tools and resources over the MCP protocol via stdio or HTTP transport.
- **MCP_Client**: The component within mcp-scan that connects to an MCP_Server to enumerate tools and issue probes.
- **Static_Analyzer**: The component that parses Python source files using the `ast` stdlib module and applies detection rules without executing code.
- **Dynamic_Prober**: The component that connects to a running MCP_Server, enumerates its tools, and sends crafted probe inputs to observe behavior.
- **Rule**: A self-contained detection unit that implements the `Rule` abstract base class, carries a rule ID (e.g., MCP001), severity, and CWE reference, and emits zero or more `Finding` objects.
- **Finding**: A pydantic model representing a single detected issue, containing rule ID, severity, file path or server URL, line number (static) or tool name (dynamic), message, and remediation guidance.
- **ScanResult**: A pydantic model aggregating all `Finding` objects from a scan run, plus metadata (scan mode, target, timestamp, tool version).
- **Severity**: An enumeration with values CRITICAL, HIGH, MEDIUM, LOW, and INFO.
- **SSRF**: Server-Side Request Forgery — a vulnerability where attacker-controlled input is used to construct HTTP requests from the server.
- **Prompt_Injection**: An attack where content in tool descriptions or tool outputs is crafted to manipulate the LLM's behavior.
- **PKCE**: Proof Key for Code Exchange — an OAuth 2.0 extension that prevents authorization code interception attacks.
- **SARIF**: Static Analysis Results Interchange Format — a JSON-based standard (version 2.1.0) for representing static analysis tool output.
- **Taint**: A data-flow label applied to values that originate from user-controlled or network-controlled sources during static analysis.
- **Allowlist**: An explicit set of permitted values or patterns against which input is validated before use.
- **CWE**: Common Weakness Enumeration — a community-developed list of software and hardware weakness types.
- **CLI**: Command-line interface, implemented with `typer`.
- **GitHub_Action**: A reusable composite GitHub Actions workflow that wraps the mcp-scan CLI for use in CI pipelines.

---

## Requirements

### Requirement 1: Core Data Models

**User Story:** As a developer integrating mcp-scan into a pipeline, I want well-typed data models for findings and scan results, so that I can programmatically consume and process scan output.

#### Acceptance Criteria

1. THE mcp-scan library SHALL define a `Severity` enumeration with values CRITICAL, HIGH, MEDIUM, LOW, and INFO.
2. THE mcp-scan library SHALL define a `Finding` pydantic model with fields: `rule_id` (string), `severity` (Severity), `target` (string), `location` (string), `message` (string), and `remediation` (string).
3. THE mcp-scan library SHALL define a `ScanResult` pydantic model with fields: `findings` (list of Finding), `scan_mode` (string), `target` (string), `timestamp` (ISO 8601 datetime string), and `tool_version` (string).
4. WHEN a `ScanResult` is serialized to JSON, THE mcp-scan library SHALL produce valid JSON that round-trips back to an equivalent `ScanResult` object.
5. THE mcp-scan library SHALL expose `Finding` and `ScanResult` as public API symbols importable from the top-level package.

---

### Requirement 2: Static Analyzer Foundation

**User Story:** As a security engineer, I want the static analyzer to walk Python ASTs and apply pluggable rules, so that new detection rules can be added without modifying the core walker.

#### Acceptance Criteria

1. THE Static_Analyzer SHALL accept a filesystem path to a Python source file or directory as input.
2. WHEN a directory path is provided, THE Static_Analyzer SHALL recursively discover all `.py` files within that directory tree.
3. THE Static_Analyzer SHALL parse each discovered `.py` file into an AST using the Python `ast` stdlib module.
4. IF a `.py` file cannot be parsed due to a syntax error, THEN THE Static_Analyzer SHALL emit a Finding with severity INFO describing the parse failure and continue processing remaining files.
5. THE Static_Analyzer SHALL apply all registered Rule instances to each parsed AST and collect the resulting Finding objects.
6. THE Rule ABC SHALL define an abstract method `check(tree: ast.AST, source_path: str) -> list[Finding]` that each concrete Rule must implement.
7. THE Static_Analyzer SHALL support auto-discovery of Rule subclasses from a designated rules package without requiring manual registration.
8. WHEN the same source file is analyzed twice with the same rules, THE Static_Analyzer SHALL produce identical Finding lists (deterministic output).

---

### Requirement 3: Taint Tracking

**User Story:** As a security engineer, I want the static analyzer to track tainted data flow from MCP tool parameters to dangerous sinks, so that SSRF and injection rules produce low false-positive results.

#### Acceptance Criteria

1. THE Static_Analyzer SHALL mark function parameters of MCP tool handler functions as tainted sources.
2. WHEN a tainted value is assigned to a new variable, THE Static_Analyzer SHALL propagate the taint label to that variable within the same function scope.
3. WHEN a tainted value is passed as an argument to a function call that is a known dangerous sink, THE Static_Analyzer SHALL record a taint flow from source to sink.
4. WHEN a tainted value is validated against an Allowlist before reaching a sink, THE Static_Analyzer SHALL not emit a Finding for that flow.
5. THE Static_Analyzer SHALL limit taint propagation to intra-procedural scope for the MVP.

---

### Requirement 4: SSRF and Request-Side Detection Rules

**User Story:** As a security engineer, I want the scanner to detect tools that pass attacker-controlled URLs or paths to HTTP clients and system calls, so that SSRF and command injection vulnerabilities are surfaced.

#### Acceptance Criteria

1. WHEN the Static_Analyzer encounters a call to `httpx.get`, `httpx.post`, `httpx.request`, `requests.get`, `requests.post`, or `requests.request` where the URL argument is tainted, THE Static_Analyzer SHALL emit a Finding with rule_id `MCP001`, severity HIGH, and CWE-918.
2. WHEN the Static_Analyzer encounters an HTTP client call that does not specify a `timeout` argument, THE Static_Analyzer SHALL emit a Finding with rule_id `MCP002` and severity LOW.
3. WHEN the Static_Analyzer encounters a call to `urllib.request.urlopen` where the URL argument is tainted, THE Static_Analyzer SHALL emit a Finding with rule_id `MCP003`, severity HIGH, and CWE-918.
4. WHEN the Static_Analyzer encounters a call to `subprocess.run`, `subprocess.call`, or `subprocess.Popen` with `shell=True` and a tainted argument, THE Static_Analyzer SHALL emit a Finding with rule_id `MCP004`, severity CRITICAL, and CWE-78.
5. WHEN the Static_Analyzer encounters a call to `open()` where the path argument is tainted, THE Static_Analyzer SHALL emit a Finding with rule_id `MCP005`, severity HIGH, and CWE-22.
6. FOR ALL Python source files that contain no SSRF or request-side issues, THE Static_Analyzer SHALL emit zero Findings for rules MCP001 through MCP005.

---

### Requirement 5: Secrets and Auth Misconfiguration Detection Rules

**User Story:** As a security engineer, I want the scanner to detect hardcoded credentials and authentication weaknesses, so that secrets are not shipped in MCP server source code.

#### Acceptance Criteria

1. WHEN the Static_Analyzer encounters a string literal assigned to a variable whose name matches patterns such as `api_key`, `apikey`, `token`, `secret`, `password`, or `passwd` (case-insensitive), THE Static_Analyzer SHALL emit a Finding with rule_id `MCP010`, severity CRITICAL.
2. WHEN the Static_Analyzer encounters a string literal assigned to a variable whose name matches patterns such as `password` or `passwd` (case-insensitive), THE Static_Analyzer SHALL emit a Finding with rule_id `MCP011`, severity CRITICAL.
3. WHEN the Static_Analyzer encounters a string literal that begins with `http://` (not `https://`) assigned to a variable or passed as an argument in a context associated with authentication or API communication, THE Static_Analyzer SHALL emit a Finding with rule_id `MCP012`, severity MEDIUM.
4. WHEN the Static_Analyzer encounters an OAuth authorization URL construction that does not include a `code_challenge` parameter, THE Static_Analyzer SHALL emit a Finding with rule_id `MCP013`, severity HIGH.
5. WHEN the Static_Analyzer encounters a call to `print()` or a logging function where a tainted token or credential variable is passed as an argument, THE Static_Analyzer SHALL emit a Finding with rule_id `MCP014`, severity HIGH.
6. FOR ALL Python source files that contain no secrets or auth misconfigurations, THE Static_Analyzer SHALL emit zero Findings for rules MCP010 through MCP014.

---

### Requirement 6: Tool Description and Prompt Injection Detection Rules

**User Story:** As a security engineer, I want the scanner to detect malicious or manipulative content in MCP tool descriptions, so that prompt injection and scope-mismatch attacks are identified.

#### Acceptance Criteria

1. WHEN the Static_Analyzer encounters a tool description string that contains Unicode characters outside the Basic Latin and Latin-1 Supplement blocks (code points above U+00FF), THE Static_Analyzer SHALL emit a Finding with rule_id `MCP020`, severity HIGH.
2. WHEN the Static_Analyzer encounters a tool description string that contains phrases matching prompt-injection patterns such as "ignore previous instructions", "disregard", "you are now", "act as", or "system prompt", THE Static_Analyzer SHALL emit a Finding with rule_id `MCP021`, severity HIGH.
3. WHEN the Static_Analyzer detects that a tool description claims capabilities or data access that are not reflected in the tool handler's function body, THE Static_Analyzer SHALL emit a Finding with rule_id `MCP022`, severity MEDIUM.
4. WHEN the Static_Analyzer detects that a tool description requests sensitive data categories (such as passwords, tokens, or private keys) that are not used within the tool handler's function body, THE Static_Analyzer SHALL emit a Finding with rule_id `MCP023`, severity HIGH.
5. FOR ALL tool descriptions that contain no hidden Unicode, injection phrases, scope mismatches, or sensitive data requests, THE Static_Analyzer SHALL emit zero Findings for rules MCP020 through MCP023.

---

### Requirement 7: Dynamic Prober — MCP Client Connection

**User Story:** As a security engineer, I want the dynamic prober to connect to a running MCP server over stdio or HTTP, so that I can analyze servers regardless of their implementation language.

#### Acceptance Criteria

1. THE Dynamic_Prober SHALL connect to an MCP_Server using the stdio transport when the target is specified as a command string.
2. THE Dynamic_Prober SHALL connect to an MCP_Server using the HTTP transport when the target is specified as an HTTP or HTTPS URL.
3. WHEN connected, THE Dynamic_Prober SHALL enumerate all tools exposed by the MCP_Server by calling the MCP `list_tools` method.
4. WHEN connected, THE Dynamic_Prober SHALL retrieve the description, input schema, and name for each enumerated tool.
5. IF the MCP_Server is unreachable or the connection times out after 30 seconds, THEN THE Dynamic_Prober SHALL emit a Finding with severity INFO describing the connection failure and terminate the dynamic scan gracefully.
6. WHEN the Dynamic_Prober completes enumeration, THE Dynamic_Prober SHALL disconnect from the MCP_Server cleanly without leaving orphaned processes or open sockets.

---

### Requirement 8: Dynamic Prober — Security Probes

**User Story:** As a security engineer, I want the dynamic prober to send crafted inputs to MCP tools and observe responses, so that runtime vulnerabilities are detected in servers of any implementation language.

#### Acceptance Criteria

1. WHEN the Dynamic_Prober identifies a tool with a string-typed parameter, THE Dynamic_Prober SHALL send an SSRF probe payload (e.g., a URL pointing to a controlled listener) and record whether the MCP_Server initiates an outbound HTTP request.
2. WHEN the Dynamic_Prober identifies a tool with a string-typed parameter, THE Dynamic_Prober SHALL send a prompt-injection probe payload (e.g., "ignore previous instructions") and record whether the payload appears unescaped in the tool's response.
3. WHEN the Dynamic_Prober identifies a tool that accepts authentication-related parameters, THE Dynamic_Prober SHALL send a plaintext HTTP URL as the endpoint value and record whether the MCP_Server accepts it without error.
4. WHEN the Dynamic_Prober sends a probe that triggers an outbound request to the controlled listener, THE Dynamic_Prober SHALL emit a Finding with rule_id `MCP001`, severity HIGH.
5. WHEN the Dynamic_Prober sends a probe payload that is reflected unescaped in the tool response, THE Dynamic_Prober SHALL emit a Finding with rule_id `MCP021`, severity HIGH.
6. THE Dynamic_Prober SHALL apply tool description analysis (rules MCP020–MCP023) to all enumerated tool descriptions regardless of transport type.

---

### Requirement 9: Output Formatters

**User Story:** As a developer, I want scan results in multiple output formats, so that I can view findings in the terminal, integrate them into CI pipelines, and import them into security dashboards.

#### Acceptance Criteria

1. THE mcp-scan CLI SHALL render scan results to the terminal using `rich` with a table showing rule ID, severity, location, and message, with severity levels color-coded (CRITICAL=red, HIGH=orange, MEDIUM=yellow, LOW=blue, INFO=white).
2. WHEN the `--format json` flag is provided, THE mcp-scan CLI SHALL write a JSON document conforming to the `ScanResult` schema to stdout.
3. WHEN the `--format sarif` flag is provided, THE mcp-scan CLI SHALL write a SARIF 2.1.0-compliant JSON document to stdout, with each Finding mapped to a SARIF `result` object.
4. WHEN the `--format markdown` flag is provided, THE mcp-scan CLI SHALL write a Markdown document with a summary table and per-finding detail sections to stdout.
5. WHEN the `--output <file>` flag is provided, THE mcp-scan CLI SHALL write the formatted output to the specified file path instead of stdout.
6. WHEN zero findings are produced, THE mcp-scan CLI SHALL display a success message indicating no issues were found, regardless of output format.
7. FOR ALL valid `ScanResult` objects, serializing to JSON and deserializing back SHALL produce an equivalent `ScanResult` (round-trip property).

---

### Requirement 10: CLI Interface

**User Story:** As a developer, I want a clear CLI with subcommands for each scan mode, so that I can run targeted scans and integrate mcp-scan into scripts and CI workflows.

#### Acceptance Criteria

1. THE mcp-scan CLI SHALL provide a `static` subcommand that accepts a `--path` argument pointing to a Python source file or directory and runs the Static_Analyzer.
2. THE mcp-scan CLI SHALL provide a `dynamic` subcommand that accepts a `--target` argument specifying a stdio command or HTTP URL and runs the Dynamic_Prober.
3. THE mcp-scan CLI SHALL provide an `all` subcommand that accepts both `--path` and `--target` arguments and runs both the Static_Analyzer and the Dynamic_Prober, merging their findings into a single `ScanResult`.
4. THE mcp-scan CLI SHALL provide a `rules` subcommand that lists all registered rules with their IDs, severity, description, and CWE reference.
5. WHEN the `--severity <level>` flag is provided, THE mcp-scan CLI SHALL filter output to include only findings at or above the specified severity level.
6. WHEN the `--rule <id>` flag is provided, THE mcp-scan CLI SHALL run only the specified rule and suppress all others.
7. WHEN the `--config <file>` flag is provided, THE mcp-scan CLI SHALL load scan configuration (ignored paths, disabled rules, severity thresholds) from the specified TOML or JSON file.
8. WHEN any scan produces one or more findings with severity HIGH or above, THE mcp-scan CLI SHALL exit with a non-zero exit code.
9. WHEN the `--version` flag is provided, THE mcp-scan CLI SHALL print the tool version string and exit with code 0.
10. WHEN an invalid subcommand or flag is provided, THE mcp-scan CLI SHALL print a usage message and exit with a non-zero exit code.

---

### Requirement 11: Configuration File Support

**User Story:** As a developer, I want to define scan configuration in a file committed to my repository, so that mcp-scan behaves consistently across all contributors and CI runs.

#### Acceptance Criteria

1. THE mcp-scan CLI SHALL accept a configuration file in TOML or JSON format specifying: disabled rule IDs, path exclusion glob patterns, minimum severity threshold, and output format.
2. WHEN a configuration file specifies a disabled rule ID, THE mcp-scan CLI SHALL not execute that rule during the scan.
3. WHEN a configuration file specifies a path exclusion glob pattern, THE Static_Analyzer SHALL skip all files whose paths match that pattern.
4. WHEN both a configuration file and a CLI flag specify conflicting values for the same setting, THE mcp-scan CLI SHALL give precedence to the CLI flag.
5. IF a configuration file is malformed or contains unrecognized keys, THEN THE mcp-scan CLI SHALL emit an error message describing the problem and exit with a non-zero exit code.

---

### Requirement 12: GitHub Action Integration

**User Story:** As a developer, I want a GitHub Action that runs mcp-scan in CI, so that pull requests are automatically checked for MCP security issues.

#### Acceptance Criteria

1. THE GitHub_Action SHALL be implemented as a composite GitHub Actions workflow that installs mcp-scan and runs the `static` subcommand against the repository checkout.
2. THE GitHub_Action SHALL accept inputs for: `path` (source directory to scan), `severity` (minimum severity to fail on), `format` (output format), and `args` (additional CLI arguments).
3. WHEN the scan produces findings at or above the configured severity threshold, THE GitHub_Action SHALL set the workflow step outcome to failure.
4. WHEN the scan produces no findings at or above the configured severity threshold, THE GitHub_Action SHALL set the workflow step outcome to success.
5. THE GitHub_Action SHALL upload the scan output as a workflow artifact when the `format` input is set to `sarif` or `json`.

---

### Requirement 13: Test Coverage and Sample Servers

**User Story:** As a contributor, I want a comprehensive test suite with sample vulnerable MCP servers, so that all detection rules are verified and regressions are caught automatically.

#### Acceptance Criteria

1. THE mcp-scan test suite SHALL include at least one positive test case (a file or server that triggers the rule) and one negative test case (a file or server that does not trigger the rule) for each of the 14 detection rules.
2. THE mcp-scan test suite SHALL include fixture Python files that contain known-vulnerable patterns for each rule, used as static analysis inputs.
3. THE mcp-scan test suite SHALL include at least one sample MCP server that exposes tools with SSRF, prompt-injection, and hardcoded-secret vulnerabilities for use as dynamic probe targets.
4. WHEN the full test suite is executed, THE mcp-scan test suite SHALL achieve a minimum line coverage of 80% across the library source code.
5. THE mcp-scan test suite SHALL include snapshot tests for each output formatter that verify the rendered output matches a stored reference for a fixed `ScanResult` input.
6. WHEN a `ScanResult` is serialized to JSON and deserialized, THE mcp-scan test suite SHALL verify the round-trip produces an equivalent object for at least 50 distinct generated `ScanResult` values (property-based test).

---

### Requirement 14: Package and Distribution

**User Story:** As a developer, I want to install mcp-scan from PyPI with a single command, so that I can start scanning without manual setup.

#### Acceptance Criteria

1. THE mcp-scan library SHALL be packaged using `pyproject.toml` with `uv` as the build and dependency management tool.
2. THE mcp-scan library SHALL declare minimum Python version 3.11 in its package metadata.
3. THE mcp-scan library SHALL declare runtime dependencies on `mcp`, `httpx`, `pydantic`, `rich`, and `typer` with pinned minimum versions.
4. WHEN installed via `pip install mcp-scan` or `uv add mcp-scan`, THE mcp-scan CLI SHALL be available as the `mcp-scan` command on the system PATH.
5. THE mcp-scan library SHALL expose a public Python API so that `from mcp_scan import Scanner, Finding, ScanResult` succeeds after installation.
