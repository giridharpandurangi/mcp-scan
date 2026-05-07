"""MCP013 positive fixture: OAuth URL construction without code_challenge — should trigger MCP013."""

client_id = "my-client-id"
redirect_uri = "https://app.example.com/callback"

# OAuth authorization URL without code_challenge — HIGH finding expected
auth_url = "https://auth.example.com/oauth/authorize?client_id=" + client_id + "&redirect_uri=" + redirect_uri
