"""MCP001 alias positive fixture: aliased import 'from httpx import get as fetch'.

This is the regression test for the alias map work in Task 4.
The rule must detect the tainted URL even when httpx.get is imported as 'fetch'.
"""
from httpx import get as fetch


@mcp.tool()
def fetch_url(url):
    # fetch is an alias for httpx.get — must still be detected as a sink
    return fetch(url)
