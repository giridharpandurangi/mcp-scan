"""Core data models for mcp-scan: Severity, Finding, ScanResult, ScanConfig, RuleMetadata."""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, field_serializer, field_validator


class Severity(str, Enum):
    """Severity levels for security findings, ordered from most to least severe."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def level(self) -> int:
        """Numeric severity rank. Higher is more severe."""
        return _SEVERITY_LEVELS[self]

    # NOTE: Severity inherits from str, so returning NotImplemented from these
    # methods would silently fall back to lexicographic str comparison rather
    # than raising TypeError. The guards are therefore omitted — within this
    # codebase comparisons are always Severity-to-Severity, and the one-liner
    # form keeps coverage clean.
    def __lt__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.level < other.level  # type: ignore[union-attr]

    def __le__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.level <= other.level  # type: ignore[union-attr]

    def __gt__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.level > other.level  # type: ignore[union-attr]

    def __ge__(self, other: "Severity") -> bool:  # type: ignore[override]
        return self.level >= other.level  # type: ignore[union-attr]


# Defined outside the class to avoid enum member confusion
_SEVERITY_LEVELS: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Finding(BaseModel):
    """A single detected security issue."""

    rule_id: str
    severity: Severity
    target: str  # file path (static) or server URL/command (dynamic)
    location: str  # "path/to/file.py:42" (static) or "tool:tool_name" (dynamic)
    message: str
    remediation: str
    confidence: Literal["HIGH", "LOW"] = "HIGH"  # LOW for dynamic findings without --ssrf-listener confirmation


class ScanResult(BaseModel):
    """Aggregated results from a scan run."""

    findings: list[Finding]
    scan_mode: Literal["static", "dynamic", "all"]
    target: str
    timestamp: datetime
    tool_version: str

    @field_serializer("timestamp")
    def serialize_timestamp(self, value: datetime) -> str:
        """Serialize datetime to ISO 8601 string."""
        return value.isoformat()

    @field_validator("timestamp", mode="before")
    @classmethod
    def parse_timestamp(cls, value: object) -> datetime:
        """Accept ISO 8601 strings as well as datetime objects."""
        if isinstance(value, str):
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        return value  # type: ignore[return-value]


class ScanConfig(BaseModel):
    """Configuration for a scan run."""

    disabled_rules: list[str] = Field(default_factory=list)
    exclude_paths: list[str] = Field(default_factory=list)  # glob patterns
    min_severity: Severity = Severity.INFO
    output_format: Literal["rich", "json", "sarif", "markdown"] = "rich"
    trusted_validators: list[str] = Field(default_factory=list)  # custom sanitizer function names


@dataclass
class RuleMetadata:
    """Static metadata for a detection rule."""

    rule_id: str
    severity: Severity
    cwe: str
    title: str
    description: str
    remediation: str
