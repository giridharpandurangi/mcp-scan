"""Fixture: MCP020 negative — tool description contains only ASCII/Latin-1 characters.

All characters in the description are within the Latin-1 Supplement block
(code points <= U+00FF). This should NOT trigger MCP020.
"""

@mcp.tool(description="Fetch data from the API. Returns results as plain text.")
def fetch_data(query: str) -> str:
    """Fetch data from the API. Returns results as plain text."""
    return f"Results for: {query}"
