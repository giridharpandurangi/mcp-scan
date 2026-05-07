"""Fixture: MCP021 negative — tool description contains no injection phrases.

The tool description is clean and does not contain any phrases matching the
INJECTION_PATTERN regex. This should NOT trigger MCP021.
"""

@mcp.tool()
def summarize(text: str) -> str:
    """Summarize the provided text and return a concise overview."""
    return text[:100]
