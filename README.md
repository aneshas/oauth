# oauth
OAuth2 cli authenticator. Supports code/pkce, authentication flows (implicit will follow)

# Installation
Install via `go get github.com/aneshas/oauth` then run `go install` from the project folder.

# Setup
Create `~/.config/oauth` folder and place `localhost.crt` and `localhost.key` provided in the repository (or
generate your own). These are needed if you are using ssl for redirect uri's. You will need to trust this certificate.

Different oauth configurations are stored as .json profiles under `~/.config/oauth`. Default profile is named `default.json`

Upon running `oauth` it will try to read `~/.config/oauth/default.json`. You can save different profiles under different names, eg. 
`webapp.json` and make oauth use that profile via flag: `oauth -p webapp`.

Example profile config:
```json
{
  "authorize_uri": "https://your.authority.com/oauth2/authorize",
  "token_uri": "https://your.authority.com/oauth2/token",
  "client_id": "xxx-client-id",
  "scope": "openid",
  "redirect_port": 5000,
  "use_ssl": true,
  "redirect_path": "/auth-callback"
}
```

or

```json
{
  "authorize_uri": "https://your.authority.com/oauth2/authorize",
  "token_uri": "https://your.authority.com/oauth2/token",
  "client_id": "aaa-bbb-ccc",
  "scope": "openid profile email",
  "redirect_path": "/auth_callback"
}
```
