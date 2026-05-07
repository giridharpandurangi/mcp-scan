"""MCP001 negative fixture: URL validated against allowlist before use — no MCP001."""
import httpx

ALLOWED_HOSTS = {"api.example.com", "data.example.com"}


@mcp.tool()
def fetch_url(url):
    from urllib.parse import urlparse
    if urlparse(url).hostname in ALLOWED_HOSTS:
        return httpx.get(url, timeout=10)
    raise ValueError("URL not allowed")
