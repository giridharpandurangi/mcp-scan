"""MCP003 negative fixture: literal URL passed to urlopen — no MCP003."""
import urllib.request


@mcp.tool()
def open_url(query):
    # Literal URL — not tainted, no MCP003
    return urllib.request.urlopen("https://api.example.com/data")
