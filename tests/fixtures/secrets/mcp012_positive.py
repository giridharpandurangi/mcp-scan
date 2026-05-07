"""MCP012 positive fixture: http:// URL in auth context — should trigger MCP012."""

# Insecure HTTP URL assigned to an auth-related variable — MEDIUM finding expected
auth_url = "http://auth.example.com/oauth/token"
