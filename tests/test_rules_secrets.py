"""Unit tests for secrets and auth misconfiguration rules MCP010–MCP014.

Task 7 — Requirements 5.1, 5.2, 5.3, 5.4, 5.5, 5.6

Structure:
- One positive fixture (vulnerable pattern → finding emitted) per rule
- One negative fixture (clean pattern → no finding) per rule
- Inline tests for edge cases and variant patterns
"""

from __future__ import annotations

import ast
import textwrap
from pathlib import Path

import pytest

from mcp_scan.models import Severity
from mcp_scan.rules.secrets import (
    Mcp010HardcodedApiKeyRule,
    Mcp011HardcodedPasswordRule,
    Mcp012InsecureHttpRule,
    Mcp013MissingPkceRule,
    Mcp014CredentialLoggingRule,
)

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "secrets"


def _load_fixture(name: str) -> tuple[ast.AST, str]:
    """Parse a fixture file and return (tree, source_path)."""
    path = FIXTURES_DIR / name
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    return tree, str(path)


def _parse_inline(source: str) -> tuple[ast.AST, str]:
    """Parse an inline source string and return (tree, source_path)."""
    src = textwrap.dedent(source)
    tree = ast.parse(src, filename="<test>")
    return tree, "<test>"


# ---------------------------------------------------------------------------
# MCP010 — Hardcoded API key / token / secret
# ---------------------------------------------------------------------------


class TestMcp010HardcodedApiKey:
    rule = Mcp010HardcodedApiKeyRule()

    def test_positive_api_key_fixture(self):
        """String literal assigned to api_key emits MCP010 CRITICAL finding."""
        tree, path = _load_fixture("mcp010_positive.py")
        findings = self.rule.check(tree, path)
        assert len(findings) == 1
        assert findings[0].rule_id == "MCP010"
        assert findings[0].severity == Severity.CRITICAL

    def test_negative_env_var_fixture(self):
        """api_key assigned from os.environ emits no MCP010."""
        tree, path = _load_fixture("mcp010_negative.py")
        findings = self.rule.check(tree, path)
        assert findings == []

    def test_token_variable_name(self):
        """String literal assigned to 'token' variable triggers MCP010."""
        tree, path = _parse_inline("""
            token = "ghp_abcdef1234567890"
        """)
        findings = self.rule.check(tree, path)
        assert len(findings) == 1
        assert findings[0].rule_id == "MCP010"

    def test_secret_variable_name(self):
        """String literal assigned to 'secret' variable triggers MCP010."""
        tree, path = _parse_inline("""
            secret = "my-super-secret-value"
        """)
        findings = self.rule.check(tree, path)
        assert len(findings) == 1
        assert findings[0].rule_id == "MCP010"

    def test_apikey_no_underscore(self):
        """String literal assigned to 'apikey' (no underscore) triggers MCP010."""
        tree, path = _parse_inline("""
            apikey = "abc123"
        """)
        findings = self.rule.check(tree, path)
        assert len(findings) == 1
        assert findings[0].rule_id == "MCP010"

    def test_case_insensitive_API_KEY(self):
        """Variable name 'API_KEY' (uppercase) triggers MCP010."""
        tree, path = _parse_inline("""
            API_KEY = "sk-prod-1234"
        """)
        findings = self.rule.check(tree, path)
        assert len(findings) == 1
        assert findings[0].rule_id == "MCP010"

    def test_empty_string_no_finding(self):
        """Empty string assigned to api_key does not trigger MCP010."""
        tree, path = _parse_inline("""
            api_key = ""
        """)
        findings = self.rule.check(tree, path)
        assert findings == []

    def test_integer_value_no_finding(self):
        """Integer assigned to api_key does not trigger MCP010."""
        tree, path = _parse_inline("""
            api_key = 12345
        """)
        findings = self.rule.check(tree, path)
        assert findings == []

    def test_none_value_no_finding(self):
        """None assigned to api_key does not trigger MCP010."""
        tree, path = _parse_inline("""
            api_key = None
        """)
        findings = self.rule.check(tree, path)
        assert findings == []

    def test_finding_location_has_line_number(self):
        """The finding location includes the line number."""
        tree, path = _parse_inline("""
            api_key = "sk-1234"
        """)
        findings = self.rule.check(tree, path)
        assert ":" in findings[0].location
        line_part = findings[0].location.split(":")[-1]
        assert line_part.isdigit()

    def test_unrelated_variable_no_finding(self):
        """String assigned to an unrelated variable name does not trigger MCP010."""
        tree, path = _parse_inline("""
            username = "alice"
            greeting = "hello world"
        """)
        findings = self.rule.check(tree, path)
        assert findings == []


# ---------------------------------------------------------------------------
# MCP011 — Hardcoded password / passwd
# ---------------------------------------------------------------------------


class TestMcp011HardcodedPassword:
    rule = Mcp011HardcodedPasswordRule()

    def test_positive_password_fixture(self):
        """String literal assigned to password emits MCP011 CRITICAL finding."""
        tree, path = _load_fixture("mcp011_positive.py")
        findings = self.rule.check(tree, path)
        assert len(findings) == 1
        assert findings[0].rule_id == "MCP011"
        assert findings[0].severity == Severity.CRITICAL

    def test_negative_env_var_fixture(self):
        """password assigned from os.environ emits no MCP011."""
        tree, path = _load_fixture("mcp011_negative.py")
        findings = self.rule.check(tree, path)
        assert findings == []

    def test_passwd_variable_name(self):
        """String literal assigned to 'passwd' triggers MCP011."""
        tree, path = _parse_inline("""
            passwd = "hunter2"
        """)
        findings = self.rule.check(tree, path)
        assert len(findings) == 1
        assert findings[0].rule_id == "MCP011"

    def test_case_insensitive_PASSWORD(self):
        """Variable name 'PASSWORD' (uppercase) triggers MCP011."""
        tree, path = _parse_inline("""
            PASSWORD = "s3cr3t"
        """)
        findings = self.rule.check(tree, path)
        assert len(findings) == 1
        assert findings[0].rule_id == "MCP011"

    def test_db_password_variable(self):
        """Variable name 'db_password' triggers MCP011."""
        tree, path = _parse_inline("""
            db_password = "mysecretpassword"
        """)
        findings = self.rule.check(tree, path)
        assert len(findings) == 1
        assert findings[0].rule_id == "MCP011"

    def test_empty_string_no_finding(self):
        """Empty string assigned to password does not trigger MCP011."""
        tree, path = _parse_inline("""
            password = ""
        """)
        findings = self.rule.check(tree, path)
        assert findings == []

    def test_function_call_no_finding(self):
        """password assigned from a function call does not trigger MCP011."""
        tree, path = _parse_inline("""
            import getpass
            password = getpass.getpass("Enter password: ")
        """)
        findings = self.rule.check(tree, path)
        assert findings == []

    def test_unrelated_variable_no_finding(self):
        """String assigned to an unrelated variable name does not trigger MCP011."""
        tree, path = _parse_inline("""
            username = "alice"
        """)
        findings = self.rule.check(tree, path)
        assert findings == []


# ---------------------------------------------------------------------------
# MCP012 — Insecure HTTP URL in auth/API context
# ---------------------------------------------------------------------------


class TestMcp012InsecureHttp:
    rule = Mcp012InsecureHttpRule()

    def test_positive_http_auth_url_fixture(self):
        """http:// URL assigned to auth_url emits MCP012 MEDIUM finding."""
        tree, path = _load_fixture("mcp012_positive.py")
        findings = self.rule.check(tree, path)
        assert len(findings) == 1
        assert findings[0].rule_id == "MCP012"
        assert findings[0].severity == Severity.MEDIUM

    def test_negative_https_auth_url_fixture(self):
        """https:// URL assigned to auth_url emits no MCP012."""
        tree, path = _load_fixture("mcp012_negative.py")
        findings = self.rule.check(tree, path)
        assert findings == []

    def test_http_api_url_variable(self):
        """http:// URL assigned to 'api_url' variable triggers MCP012."""
        tree, path = _parse_inline("""
            api_url = "http://api.example.com/v1"
        """)
        findings = self.rule.check(tree, path)
        assert len(findings) == 1
        assert findings[0].rule_id == "MCP012"

    def test_http_endpoint_variable(self):
        """http:// URL assigned to 'endpoint' variable triggers MCP012."""
        tree, path = _parse_inline("""
            endpoint = "http://service.internal/auth"
        """)
        findings = self.rule.check(tree, path)
        assert len(findings) == 1
        assert findings[0].rule_id == "MCP012"

    def test_http_base_url_variable(self):
        """http:// URL assigned to 'base_url' variable triggers MCP012."""
        tree, path = _parse_inline("""
            base_url = "http://api.example.com"
        """)
        findings = self.rule.check(tree, path)
        assert len(findings) == 1
        assert findings[0].rule_id == "MCP012"

    def test_https_url_no_finding(self):
        """https:// URL in auth context does not trigger MCP012."""
        tree, path = _parse_inline("""
            auth_url = "https://auth.example.com/token"
        """)
        findings = self.rule.check(tree, path)
        assert findings == []

    def test_http_unrelated_variable_no_finding(self):
        """http:// URL assigned to an unrelated variable name does not trigger MCP012."""
        tree, path = _parse_inline("""
            documentation_link = "http://docs.example.com"
        """)
        findings = self.rule.check(tree, path)
        assert findings == []

    def test_http_passed_to_http_client(self):
        """http:// URL passed directly to an HTTP client call triggers MCP012."""
        tree, path = _parse_inline("""
            import requests
            response = requests.get("http://api.example.com/data")
        """)
        findings = self.rule.check(tree, path)
        assert len(findings) == 1
        assert findings[0].rule_id == "MCP012"

    def test_https_passed_to_http_client_no_finding(self):
        """https:// URL passed to HTTP client does not trigger MCP012."""
        tree, path = _parse_inline("""
            import requests
            response = requests.get("https://api.example.com/data")
        """)
        findings = self.rule.check(tree, path)
        assert findings == []

    def test_http_url_kwarg_to_http_client(self):
        """http:// URL passed as url= keyword arg to HTTP client triggers MCP012."""
        tree, path = _parse_inline("""
            import httpx
            response = httpx.get(url="http://insecure.example.com/api")
        """)
        findings = self.rule.check(tree, path)
        assert len(findings) == 1
        assert findings[0].rule_id == "MCP012"

    def test_http_base_url_kwarg_to_http_client(self):
        """http:// URL passed as base_url= keyword arg to HTTP client triggers MCP012."""
        tree, path = _parse_inline("""
            import requests
            response = requests.post(base_url="http://insecure.example.com", data={})
        """)
        findings = self.rule.check(tree, path)
        assert len(findings) == 1
        assert findings[0].rule_id == "MCP012"

    def test_https_url_kwarg_no_finding(self):
        """https:// URL passed as url= keyword arg does not trigger MCP012."""
        tree, path = _parse_inline("""
            import httpx
            response = httpx.get(url="https://secure.example.com/api")
        """)
        findings = self.rule.check(tree, path)
        assert findings == []

    def test_call_is_http_client_non_name_attribute_returns_false(self):
        """A call like obj.method.get(...) where outer value is not a Name does not crash."""
        # This exercises the return False branch in _call_is_http_client
        # when func is an Attribute but func.value is itself an Attribute with
        # a non-Name inner value (e.g., a[0].get(...))
        tree, path = _parse_inline("""
            items = [None]
            items[0].get("http://example.com")
        """)
        # Should not raise and should produce no MCP012 finding
        findings = self.rule.check(tree, path)
        # No finding expected — the call is not a recognized HTTP client
        assert all(f.rule_id != "MCP012" for f in findings)


# ---------------------------------------------------------------------------
# MCP013 — OAuth URL construction without code_challenge (missing PKCE)
# ---------------------------------------------------------------------------


class TestMcp013MissingPkce:
    rule = Mcp013MissingPkceRule()

    def test_positive_oauth_no_code_challenge_fixture(self):
        """OAuth URL without code_challenge emits MCP013 HIGH finding."""
        tree, path = _load_fixture("mcp013_positive.py")
        findings = self.rule.check(tree, path)
        assert len(findings) >= 1
        assert any(f.rule_id == "MCP013" for f in findings)
        assert all(f.severity == Severity.HIGH for f in findings if f.rule_id == "MCP013")

    def test_negative_oauth_with_code_challenge_fixture(self):
        """OAuth URL with code_challenge emits no MCP013."""
        tree, path = _load_fixture("mcp013_negative.py")
        findings = self.rule.check(tree, path)
        mcp013 = [f for f in findings if f.rule_id == "MCP013"]
        assert mcp013 == []

    def test_authorize_url_no_code_challenge(self):
        """String containing 'authorize' without code_challenge triggers MCP013."""
        tree, path = _parse_inline("""
            auth_url = "https://provider.example.com/authorize?client_id=abc"
        """)
        findings = self.rule.check(tree, path)
        assert len(findings) == 1
        assert findings[0].rule_id == "MCP013"

    def test_oauth_url_with_code_challenge_no_finding(self):
        """OAuth URL with code_challenge does not trigger MCP013."""
        tree, path = _parse_inline("""
            auth_url = "https://provider.example.com/oauth/authorize?code_challenge=abc123"
        """)
        findings = self.rule.check(tree, path)
        assert findings == []

    def test_fstring_oauth_no_code_challenge(self):
        """f-string OAuth URL without code_challenge triggers MCP013."""
        tree, path = _parse_inline("""
            client_id = "my-client"
            auth_url = f"https://auth.example.com/oauth/authorize?client_id={client_id}"
        """)
        findings = self.rule.check(tree, path)
        assert len(findings) == 1
        assert findings[0].rule_id == "MCP013"

    def test_fstring_oauth_with_code_challenge_no_finding(self):
        """f-string OAuth URL with code_challenge does not trigger MCP013."""
        tree, path = _parse_inline("""
            client_id = "my-client"
            challenge = "abc123"
            auth_url = f"https://auth.example.com/oauth/authorize?client_id={client_id}&code_challenge={challenge}"
        """)
        findings = self.rule.check(tree, path)
        assert findings == []

    def test_non_oauth_url_no_finding(self):
        """A URL that does not contain oauth/authorize/auth keywords does not trigger MCP013."""
        tree, path = _parse_inline("""
            api_url = "https://api.example.com/users?page=1"
        """)
        findings = self.rule.check(tree, path)
        assert findings == []

    def test_bare_expression_call_oauth_no_code_challenge(self):
        """OAuth URL passed directly as arg to a call (bare expression) triggers MCP013."""
        tree, path = _parse_inline("""
            import requests
            requests.get(f"https://oauth.example.com/authorize?client_id=abc&redirect_uri=https://app.example.com/cb")
        """)
        findings = self.rule.check(tree, path)
        assert len(findings) == 1
        assert findings[0].rule_id == "MCP013"

    def test_bare_expression_call_oauth_with_code_challenge_no_finding(self):
        """OAuth URL with code_challenge in a bare call expression does not trigger MCP013."""
        tree, path = _parse_inline("""
            import requests
            requests.get(f"https://oauth.example.com/authorize?client_id=abc&code_challenge=xyz")
        """)
        findings = self.rule.check(tree, path)
        assert findings == []


# ---------------------------------------------------------------------------
# MCP014 — Credential variable passed to print() or logging
# ---------------------------------------------------------------------------


class TestMcp014CredentialLogging:
    rule = Mcp014CredentialLoggingRule()

    def test_positive_print_api_key_fixture(self):
        """Credential variable passed to print() emits MCP014 HIGH finding."""
        tree, path = _load_fixture("mcp014_positive.py")
        findings = self.rule.check(tree, path)
        assert len(findings) >= 1
        assert any(f.rule_id == "MCP014" for f in findings)
        assert all(f.severity == Severity.HIGH for f in findings if f.rule_id == "MCP014")

    def test_negative_non_credential_print_fixture(self):
        """Non-credential variable passed to print() emits no MCP014."""
        tree, path = _load_fixture("mcp014_negative.py")
        findings = self.rule.check(tree, path)
        assert findings == []

    def test_logging_credential_variable(self):
        """Credential variable passed to logging.info() triggers MCP014."""
        tree, path = _parse_inline("""
            import logging
            api_key = "sk-1234"
            logging.info(api_key)
        """)
        findings = self.rule.check(tree, path)
        assert len(findings) >= 1
        assert any(f.rule_id == "MCP014" for f in findings)

    def test_print_token_variable(self):
        """Token variable passed to print() triggers MCP014."""
        tree, path = _parse_inline("""
            token = "bearer-abc123"
            print(token)
        """)
        findings = self.rule.check(tree, path)
        assert len(findings) >= 1
        assert any(f.rule_id == "MCP014" for f in findings)

    def test_print_password_variable(self):
        """Password variable passed to print() triggers MCP014."""
        tree, path = _parse_inline("""
            password = "hunter2"
            print(password)
        """)
        findings = self.rule.check(tree, path)
        assert len(findings) >= 1
        assert any(f.rule_id == "MCP014" for f in findings)

    def test_print_non_credential_no_finding(self):
        """Non-credential variable passed to print() does not trigger MCP014."""
        tree, path = _parse_inline("""
            username = "alice"
            print(username)
        """)
        findings = self.rule.check(tree, path)
        assert findings == []

    def test_credential_from_env_no_finding(self):
        """Credential variable loaded from env (not a string literal) does not trigger MCP014."""
        tree, path = _parse_inline("""
            import os
            import logging
            api_key = os.environ.get("API_KEY")
            logging.info(api_key)
        """)
        findings = self.rule.check(tree, path)
        assert findings == []

    def test_logger_debug_credential(self):
        """Credential variable passed to logger.debug() triggers MCP014."""
        tree, path = _parse_inline("""
            import logging
            logger = logging.getLogger(__name__)
            secret = "my-secret-value"
            logger.debug(secret)
        """)
        findings = self.rule.check(tree, path)
        assert len(findings) >= 1
        assert any(f.rule_id == "MCP014" for f in findings)

    def test_print_literal_string_no_finding(self):
        """Printing a literal string (not a credential variable) does not trigger MCP014."""
        tree, path = _parse_inline("""
            api_key = "sk-1234"
            print("Starting application")
        """)
        findings = self.rule.check(tree, path)
        assert findings == []

    def test_module_level_print_credential(self):
        """Module-level print of a credential variable (outside any function) triggers MCP014."""
        tree, path = _parse_inline("""
            api_key = "sk-prod-secret"
            print(api_key)
        """)
        findings = self.rule.check(tree, path)
        assert len(findings) >= 1
        assert any(f.rule_id == "MCP014" for f in findings)

    def test_module_level_logger_info_credential(self):
        """Module-level logger.info of a credential variable triggers MCP014."""
        tree, path = _parse_inline("""
            import logging
            logger = logging.getLogger(__name__)
            token = "bearer-xyz"
            logger.info(token)
        """)
        findings = self.rule.check(tree, path)
        assert len(findings) >= 1
        assert any(f.rule_id == "MCP014" for f in findings)

    def test_module_level_print_non_credential_no_finding(self):
        """Module-level print of a non-credential variable does not trigger MCP014."""
        tree, path = _parse_inline("""
            username = "alice"
            print(username)
        """)
        findings = self.rule.check(tree, path)
        assert findings == []

    def test_function_uses_module_level_credential(self):
        """Credential defined at module level and printed inside a function triggers MCP014."""
        tree, path = _parse_inline("""
            api_key = "sk-prod-secret"

            def report():
                print(api_key)
        """)
        findings = self.rule.check(tree, path)
        assert len(findings) >= 1
        assert any(f.rule_id == "MCP014" for f in findings)

    def test_function_uses_module_level_credential_logging(self):
        """Credential defined at module level and logged inside a function triggers MCP014."""
        tree, path = _parse_inline("""
            import logging
            token = "bearer-xyz"

            def send_request():
                logging.warning(token)
        """)
        findings = self.rule.check(tree, path)
        assert len(findings) >= 1
        assert any(f.rule_id == "MCP014" for f in findings)

    def test_function_prints_non_credential_with_module_credential_present(self):
        """Function prints a non-credential var while a module-level credential exists — no finding."""
        tree, path = _parse_inline("""
            api_key = "sk-secret"

            def greet():
                print("hello world")
        """)
        findings = self.rule.check(tree, path)
        assert findings == []

    def test_function_prints_untainted_name_with_credential_present(self):
        """Function prints an untainted Name arg while a credential exists — no finding from taint check."""
        tree, path = _parse_inline("""
            api_key = "sk-secret"

            def greet(username):
                print(username)
        """)
        findings = self.rule.check(tree, path)
        assert findings == []

    def test_function_with_non_sink_call_and_credential_present(self):
        """Function with a non-print/logging call while credential exists — continue branch covered."""
        tree, path = _parse_inline("""
            api_key = "sk-secret"

            def process():
                result = some_function(api_key)
                return result
        """)
        findings = self.rule.check(tree, path)
        # some_function is not a print/logging sink, so no MCP014 finding
        assert findings == []


# ---------------------------------------------------------------------------
# MCP010–014 no-false-positives on clean files (Requirement 5.6)
# ---------------------------------------------------------------------------


class TestNoFalsePositivesOnCleanFiles:
    """For files with no secrets/auth issues, all five rules emit zero findings."""

    ALL_RULES = [
        Mcp010HardcodedApiKeyRule(),
        Mcp011HardcodedPasswordRule(),
        Mcp012InsecureHttpRule(),
        Mcp013MissingPkceRule(),
        Mcp014CredentialLoggingRule(),
    ]

    def _check_all(self, source: str) -> list:
        tree, path = _parse_inline(source)
        findings = []
        for rule in self.ALL_RULES:
            findings.extend(rule.check(tree, path))
        return findings

    def test_env_var_credentials_no_findings(self):
        """Credentials loaded from environment variables produce no findings."""
        findings = self._check_all("""
            import os
            api_key = os.environ.get("API_KEY")
            password = os.environ.get("DB_PASSWORD")
        """)
        assert findings == []

    def test_https_urls_no_findings(self):
        """HTTPS URLs in auth context produce no findings."""
        findings = self._check_all("""
            auth_url = "https://auth.example.com/oauth/token"
            api_url = "https://api.example.com/v1"
        """)
        assert findings == []

    def test_oauth_with_pkce_no_findings(self):
        """OAuth URL with code_challenge produces no MCP013 finding."""
        findings = self._check_all("""
            auth_url = "https://auth.example.com/oauth/authorize?code_challenge=abc123"
        """)
        assert findings == []

    def test_print_non_credential_no_findings(self):
        """Printing non-credential variables produces no findings."""
        findings = self._check_all("""
            username = "alice"
            status = "active"
            print(username, status)
        """)
        assert findings == []

    def test_empty_module_no_findings(self):
        """An empty module produces no findings from any rule."""
        findings = self._check_all("")
        assert findings == []
