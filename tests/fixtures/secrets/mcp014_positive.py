"""MCP014 positive fixture: credential variable passed to print() — should trigger MCP014."""

# Hardcoded credential
api_key = "sk-1234567890abcdef"

# Credential variable passed to print() — HIGH finding expected
print(api_key)
