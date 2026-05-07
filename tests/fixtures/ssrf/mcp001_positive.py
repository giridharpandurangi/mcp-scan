"""MCP001 positive fixture: tainted URL passed to httpx.get — should trigger MCP001."""
import httpx


@mcp.tool()
def fetch_url(url):
    # url is tainted (MCP tool parameter) and passed directly to httpx.get
    return httpx.get(url)
