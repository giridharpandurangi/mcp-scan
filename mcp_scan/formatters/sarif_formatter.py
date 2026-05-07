"""SARIF 2.1.0 formatter for mcp-scan results."""

import json

from mcp_scan.models import Severity, ScanResult

_SEVERITY_TO_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# CWE help URIs for known rule IDs
_CWE_HELP_URIS: dict[str, str] = {
    "CWE-918": "https://cwe.mitre.org/data/definitions/918.html",
    "CWE-78": "https://cwe.mitre.org/data/definitions/78.html",
    "CWE-22": "https://cwe.mitre.org/data/definitions/22.html",
    "CWE-798": "https://cwe.mitre.org/data/definitions/798.html",
    "CWE-319": "https://cwe.mitre.org/data/definitions/319.html",
    "CWE-601": "https://cwe.mitre.org/data/definitions/601.html",
    "CWE-532": "https://cwe.mitre.org/data/definitions/532.html",
    "CWE-116": "https://cwe.mitre.org/data/definitions/116.html",
}


def _parse_location(location: str) -> tuple[str, int]:
    """Parse a location string like 'src/server.py:42' into (uri, line).

    Falls back to (location, 1) if the format is unexpected.
    """
    if ":" in location:
        parts = location.rsplit(":", 1)
        try:
            return parts[0], int(parts[1])
        except (ValueError, IndexError):
            pass
    return location, 1


class SarifFormatter:
    """Renders scan results as a SARIF 2.1.0-compliant JSON document."""

    def format(self, result: ScanResult) -> str:
        """Render a ScanResult to a SARIF 2.1.0 JSON string."""
        # Collect unique rule IDs from findings
        seen_rule_ids: set[str] = set()
        rules: list[dict] = []
        for finding in result.findings:
            if finding.rule_id not in seen_rule_ids:
                seen_rule_ids.add(finding.rule_id)
                rule_entry: dict = {
                    "id": finding.rule_id,
                    "name": _rule_id_to_name(finding.rule_id),
                    "shortDescription": {"text": finding.message},
                    "properties": {"tags": ["security"]},
                }
                # Add helpUri if we can derive a CWE URI from the rule ID
                help_uri = _rule_id_to_help_uri(finding.rule_id)
                if help_uri:
                    rule_entry["helpUri"] = help_uri
                rules.append(rule_entry)

        # Build SARIF results
        sarif_results: list[dict] = []
        for finding in result.findings:
            uri, start_line = _parse_location(finding.location)
            level = _SEVERITY_TO_LEVEL.get(finding.severity, "note")
            sarif_result: dict = {
                "ruleId": finding.rule_id,
                "level": level,
                "message": {"text": finding.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri},
                            "region": {"startLine": start_line},
                        }
                    }
                ],
            }
            sarif_results.append(sarif_result)

        document = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "mcp-scan",
                            "version": result.tool_version,
                            "rules": rules,
                        }
                    },
                    "results": sarif_results,
                }
            ],
        }

        return json.dumps(document, indent=2)


def _rule_id_to_name(rule_id: str) -> str:
    """Convert a rule ID like 'MCP001' to a camel-case name."""
    _RULE_NAMES: dict[str, str] = {
        "MCP001": "TaintedUrlSsrf",
        "MCP002": "MissingHttpTimeout",
        "MCP003": "UrllibTaintedUrl",
        "MCP004": "SubprocessShellInjection",
        "MCP005": "TaintedOpenPath",
        "MCP010": "HardcodedApiKey",
        "MCP011": "HardcodedPassword",
        "MCP012": "InsecureHttpUrl",
        "MCP013": "OAuthMissingPkce",
        "MCP014": "CredentialLogging",
        "MCP020": "UnicodeInToolDescription",
        "MCP021": "PromptInjectionInDescription",
        "PARSE_ERROR": "ParseError",
    }
    return _RULE_NAMES.get(rule_id, rule_id)


def _rule_id_to_help_uri(rule_id: str) -> str | None:
    """Return a CWE help URI for a known rule ID, or None."""
    _RULE_CWE_URIS: dict[str, str] = {
        "MCP001": _CWE_HELP_URIS["CWE-918"],
        "MCP003": _CWE_HELP_URIS["CWE-918"],
        "MCP004": _CWE_HELP_URIS["CWE-78"],
        "MCP005": _CWE_HELP_URIS["CWE-22"],
        "MCP010": _CWE_HELP_URIS["CWE-798"],
        "MCP011": _CWE_HELP_URIS["CWE-798"],
        "MCP012": _CWE_HELP_URIS["CWE-319"],
        "MCP013": _CWE_HELP_URIS["CWE-601"],
        "MCP014": _CWE_HELP_URIS["CWE-532"],
        "MCP020": _CWE_HELP_URIS["CWE-116"],
        "MCP021": _CWE_HELP_URIS["CWE-116"],
    }
    return _RULE_CWE_URIS.get(rule_id)
