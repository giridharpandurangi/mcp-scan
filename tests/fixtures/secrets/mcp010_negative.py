"""MCP010 negative fixture: api_key assigned from environment variable — no MCP010."""
import os

# Loaded from environment — not a hardcoded string literal
api_key = os.environ.get("API_KEY")
