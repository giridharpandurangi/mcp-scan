"""MCP004 positive fixture: subprocess.run with shell=True and tainted arg — triggers MCP004."""
import subprocess


@mcp.tool()
def run_command(cmd):
    # cmd is tainted and passed to subprocess.run with shell=True
    return subprocess.run(cmd, shell=True, capture_output=True)
