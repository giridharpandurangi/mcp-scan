"""MCP004 negative fixture: subprocess.run without shell=True — no MCP004."""
import subprocess


@mcp.tool()
def run_command(cmd):
    # shell=True is absent — no MCP004 even with tainted arg
    return subprocess.run(["ls", "-la"], capture_output=True)
