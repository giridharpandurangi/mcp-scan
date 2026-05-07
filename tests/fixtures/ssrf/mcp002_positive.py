"""MCP002 positive fixture: HTTP client call missing timeout — should trigger MCP002."""
import httpx


@mcp.tool()
def fetch_data(url):
    # No timeout= argument — should trigger MCP002
    return httpx.get("https://api.example.com/data")
