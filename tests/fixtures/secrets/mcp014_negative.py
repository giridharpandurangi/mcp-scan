"""MCP014 negative fixture: non-credential variable passed to print() — no MCP014."""

# Non-credential variable
username = "alice"

# Printing a non-credential variable — no finding expected
print(username)
