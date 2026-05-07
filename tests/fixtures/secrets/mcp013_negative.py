"""MCP013 negative fixture: OAuth URL construction with code_challenge — no MCP013."""

client_id = "my-client-id"
redirect_uri = "https://app.example.com/callback"
code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

# OAuth authorization URL with code_challenge (PKCE) — no finding expected
auth_url = (
    "https://auth.example.com/oauth/authorize"
    "?client_id=" + client_id
    + "&redirect_uri=" + redirect_uri
    + "&code_challenge=" + code_challenge
    + "&code_challenge_method=S256"
)
