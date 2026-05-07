"""Configuration loading for mcp-scan: TOML and JSON support."""

from __future__ import annotations

import json
import sys
import warnings
from pathlib import Path

from pydantic import ValidationError

from mcp_scan.models import ScanConfig

# tomllib is stdlib in Python 3.11+
if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    try:
        import tomllib  # type: ignore[no-redef]
    except ImportError:
        import tomli as tomllib  # type: ignore[no-redef]

# The set of valid field names for ScanConfig
_SCAN_CONFIG_FIELDS = set(ScanConfig.model_fields.keys())


def _extract_config_data(raw: dict) -> dict:
    """Extract config data from a raw parsed dict.

    Supports two layouts:
    - Flat top-level: ``{"disabled_rules": [...], ...}``
    - Nested ``[tool.mcp-scan]`` section (pyproject.toml style):
      ``{"tool": {"mcp-scan": {"disabled_rules": [...], ...}}}``

    Returns the innermost config dict.
    """
    # Check for [tool.mcp-scan] section first
    tool_section = raw.get("tool")
    if isinstance(tool_section, dict):
        mcp_scan_section = tool_section.get("mcp-scan")
        if isinstance(mcp_scan_section, dict):
            return mcp_scan_section

    # Fall back to flat top-level structure
    return raw


def _check_unrecognized_keys(data: dict) -> None:
    """Emit a warning for any keys in *data* that are not in ScanConfig.

    Unrecognized keys are ignored — the config is still loaded with the
    recognized keys. A ``UserWarning`` is issued for each unrecognized key
    so that callers can surface the message to the user (e.g., via stderr).

    Args:
        data: The flat config dict (after section extraction).
    """
    unrecognized = set(data.keys()) - _SCAN_CONFIG_FIELDS
    if unrecognized:
        keys_str = ", ".join(sorted(unrecognized))
        warnings.warn(
            f"Configuration file contains unrecognized keys: {keys_str}. "
            f"Valid keys are: {', '.join(sorted(_SCAN_CONFIG_FIELDS))}",
            UserWarning,
            stacklevel=3,
        )


def load_config(path: str | Path) -> ScanConfig:
    """Load ScanConfig from a TOML or JSON file.

    Supports:
    - ``.toml`` files (flat top-level or ``[tool.mcp-scan]`` section)
    - ``.json`` files (flat top-level structure)

    Args:
        path: Path to the configuration file.

    Returns:
        A validated :class:`ScanConfig` instance.

    Raises:
        FileNotFoundError: If the config file does not exist.
        ValueError: If the file is malformed or has invalid field values.
            Unrecognized keys emit a ``UserWarning`` but do not raise.
    """
    path = Path(path)

    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {path}")

    suffix = path.suffix.lower()

    if suffix == ".toml":
        try:
            with path.open("rb") as f:
                raw = tomllib.load(f)
        except Exception as exc:
            raise ValueError(f"Failed to parse TOML configuration file '{path}': {exc}") from exc

    elif suffix == ".json":
        try:
            with path.open("r", encoding="utf-8") as f:
                raw = json.load(f)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Failed to parse JSON configuration file '{path}': {exc}"
            ) from exc
        if not isinstance(raw, dict):
            raise ValueError(
                f"JSON configuration file '{path}' must contain a JSON object at the top level."
            )

    else:
        raise ValueError(
            f"Unsupported configuration file format '{suffix}'. "
            "Use '.toml' or '.json'."
        )

    # Extract the relevant section (handles [tool.mcp-scan] nesting)
    data = _extract_config_data(raw)

    # Warn about unrecognized keys (but continue — do not raise)
    _check_unrecognized_keys(data)

    # Filter out unrecognized keys so Pydantic doesn't reject them
    recognized_data = {k: v for k, v in data.items() if k in _SCAN_CONFIG_FIELDS}

    # Validate and construct ScanConfig via Pydantic
    try:
        return ScanConfig(**recognized_data)
    except ValidationError as exc:
        raise ValueError(
            f"Invalid configuration values in '{path}': {exc}"
        ) from exc
