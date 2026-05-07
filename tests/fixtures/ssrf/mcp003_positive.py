"""MCP003 positive fixture: tainted URL passed to urllib.request.urlopen — triggers MCP003."""
import urllib.request


@mcp.tool()
def open_url(url):
    # url is tainted and passed directly to urlopen
    return urllib.request.urlopen(url)
