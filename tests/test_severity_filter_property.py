"""Property-based tests for severity filter monotonicity.

# Feature: mcp-scan, Property 6: Severity filter monotonicity

**Validates: Requirements 10.5**

Property 6: For any ScanResult containing findings with mixed severity levels,
and for any two severity levels S1 and S2 where S1 <= S2 (S1 is less strict),
the set of findings returned when filtering at S1 SHALL be a superset (non-strict)
of the findings returned when filtering at S2.

Formally: filter(result, S1) ⊇ filter(result, S2) when S1 <= S2.
"""

from __future__ import annotations

from datetime import datetime, timezone

from hypothesis import given, settings
from hypothesis import strategies as st
from hypothesis.strategies import SearchStrategy

from mcp_scan.models import Finding, ScanConfig, ScanResult, Severity
from mcp_scan.scanner import _apply_severity_filter

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

severity_strategy: SearchStrategy[Severity] = st.sampled_from(list(Severity))

confidence_strategy: SearchStrategy[str] = st.sampled_from(["HIGH", "LOW"])

finding_strategy: SearchStrategy[Finding] = st.builds(
    Finding,
    rule_id=st.from_regex(r"MCP\d{3}", fullmatch=True),
    severity=severity_strategy,
    target=st.text(min_size=1, max_size=100),
    location=st.text(min_size=1, max_size=100),
    message=st.text(min_size=1, max_size=200),
    remediation=st.text(min_size=1, max_size=200),
    confidence=confidence_strategy,
)

scan_mode_strategy: SearchStrategy[str] = st.sampled_from(["static", "dynamic", "all"])

timestamp_strategy = st.datetimes(
    min_value=datetime(2000, 1, 1),
    max_value=datetime(2099, 12, 31),
    timezones=st.just(timezone.utc),
)

scan_result_strategy: SearchStrategy[ScanResult] = st.builds(
    ScanResult,
    findings=st.lists(finding_strategy, min_size=0, max_size=20),
    scan_mode=scan_mode_strategy,
    target=st.text(min_size=1, max_size=100),
    timestamp=timestamp_strategy,
    tool_version=st.from_regex(r"\d+\.\d+\.\d+", fullmatch=True),
)


@st.composite
def two_ordered_severities(draw) -> tuple[Severity, Severity]:
    """Draw two severity levels S1 and S2 where S1 <= S2 (S1 is less strict).

    S1 <= S2 means S1 has a lower or equal numeric level, so filtering at S1
    is more permissive (returns more findings) than filtering at S2.
    """
    all_severities = list(Severity)
    s1 = draw(st.sampled_from(all_severities))
    # S2 must be >= S1 (same or stricter threshold)
    stricter_or_equal = [s for s in all_severities if s >= s1]
    s2 = draw(st.sampled_from(stricter_or_equal))
    return s1, s2


# ---------------------------------------------------------------------------
# Property 6: Severity filter monotonicity
# ---------------------------------------------------------------------------


@settings(max_examples=25)
@given(result=scan_result_strategy, severities=two_ordered_severities())
def test_severity_filter_monotonicity(
    result: ScanResult,
    severities: tuple[Severity, Severity],
) -> None:
    """Property 6: Severity filter monotonicity.

    For any ScanResult and any two severity levels S1 <= S2 (S1 is less strict),
    filtering at S1 SHALL return a superset of the findings returned at S2.

    Formally: filter(result, S1) ⊇ filter(result, S2) when S1 <= S2.

    This is a monotonicity invariant: tightening the severity threshold can only
    remove findings, never add new ones.

    # Feature: mcp-scan, Property 6: Severity filter monotonicity
    **Validates: Requirements 10.5**
    """
    s1, s2 = severities

    # S1 is less strict (lower or equal level), S2 is stricter (higher or equal level)
    assert s1 <= s2, f"Precondition violated: S1={s1} should be <= S2={s2}"

    config_s1 = ScanConfig(min_severity=s1)
    config_s2 = ScanConfig(min_severity=s2)

    filtered_s1 = _apply_severity_filter(result, config_s1)
    filtered_s2 = _apply_severity_filter(result, config_s2)

    # Build sets of finding identities for superset check.
    # We use the index-based identity from the original findings list to handle
    # duplicate findings correctly (two identical findings are distinct items).
    # Map each finding to its position in the original list.
    original_findings = list(result.findings)

    def finding_indices(findings: list[Finding]) -> set[int]:
        """Return the set of original indices for the given filtered findings."""
        remaining = list(original_findings)
        indices: set[int] = set()
        for f in findings:
            # Find the first occurrence in remaining (to handle duplicates)
            for i, orig in enumerate(remaining):
                if orig == f:
                    # Compute the actual index in the original list
                    offset = len(original_findings) - len(remaining)
                    indices.add(offset + i)
                    remaining = remaining[i + 1 :]
                    break
        return indices

    indices_s1 = finding_indices(filtered_s1.findings)
    indices_s2 = finding_indices(filtered_s2.findings)

    # filter(result, S1) ⊇ filter(result, S2): every finding in S2 must also be in S1
    assert indices_s2.issubset(indices_s1), (
        f"Monotonicity violated: filter at S1={s1.value} is NOT a superset of "
        f"filter at S2={s2.value}.\n"
        f"Findings at S1 ({len(filtered_s1.findings)}): "
        f"{[f.severity.value for f in filtered_s1.findings]}\n"
        f"Findings at S2 ({len(filtered_s2.findings)}): "
        f"{[f.severity.value for f in filtered_s2.findings]}\n"
        f"Indices in S2 not in S1: {indices_s2 - indices_s1}"
    )

    # Additional sanity check: count-based monotonicity
    # |filter(result, S1)| >= |filter(result, S2)|
    assert len(filtered_s1.findings) >= len(filtered_s2.findings), (
        f"Count monotonicity violated: filtering at S1={s1.value} returned "
        f"{len(filtered_s1.findings)} findings, but filtering at S2={s2.value} "
        f"returned {len(filtered_s2.findings)} findings (more than S1)."
    )
