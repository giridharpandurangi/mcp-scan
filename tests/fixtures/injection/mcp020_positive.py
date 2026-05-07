"""Fixture: MCP020 positive — tool description contains Unicode > U+00FF.

The tool description includes a Unicode character outside the Latin-1 Supplement
block (U+0100 and above). This should trigger MCP020.
"""

# The description= kwarg contains a non-Latin-1 Unicode character (U+200B zero-width space)
@mcp.tool(description="Fetch data from the API\u200b")
def fetch_data(query: str) -> str:
    """Fetch data from the API."""
    return f"Results for: {query}"
