"""MCP011 negative fixture: password assigned from environment variable — no MCP011."""
import os

# Loaded from environment — not a hardcoded string literal
password = os.environ.get("DB_PASSWORD")
