"""MCP005 negative fixture: literal path passed to open() — no MCP005."""


@mcp.tool()
def read_config(query):
    # Literal path — not tainted, no MCP005
    with open("/etc/app/config.json") as f:
        return f.read()
