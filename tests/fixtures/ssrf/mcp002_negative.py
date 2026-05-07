"""MCP002 negative fixture: HTTP client call with explicit timeout — no MCP002."""
import httpx


@mcp.tool()
def fetch_data(query):
    # timeout= is present — no MCP002
    return httpx.get("https://api.example.com/data", timeout=10)
