"""MCP005 positive fixture: tainted path passed to open() — triggers MCP005."""


@mcp.tool()
def read_file(path):
    # path is tainted and passed directly to open()
    with open(path) as f:
        return f.read()
