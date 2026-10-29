# MCP OAuth Server (example)

A minimal OAuth 2.1 authorization server you can use with an MCPCore server in **OAuth 2.0** mode. It runs on plain Node.js with Express. No database is needed.

It implements everything an MCP client needs:

| Endpoint | Spec |
|---|---|
| `GET /.well-known/oauth-authorization-server` | RFC 8414 authorization server metadata |
| `GET /.well-known/openid-configuration` | Same document, for clients that look here first |
| `GET /jwks` | Public signing keys (RS256, `kid`, `use: sig`) |
| `POST /register` | RFC 7591 Dynamic Client Registration (public clients) |
| `GET/POST /authorize` | Authorization code flow with mandatory PKCE S256 and RFC 8707 `resource` |
| `POST /token` | `authorization_code` and `refresh_token` (rotated on every use) |

Access tokens are JWTs whose `aud` claim is exactly the MCP resource URL, for example `https://my-server.mcpcore.io/mcp`. This is what MCPCore checks.

> This is a starting point, not a production identity provider. Users, clients and tokens live in memory, and there is a single demo account. Replace them with your own user store before going live.

## Run it

```bash
npm install
cp .env.example .env
npm start
```

Set these values in `.env`:

| Variable | Description |
|---|---|
| `ISSUER` | Public HTTPS URL of this server, without a trailing slash. It must match the URL MCP clients reach. |
| `RESOURCE_PATTERN` | Regular expression for allowed MCP resource URLs. The default allows any `*.mcpcore.io/mcp` server. Narrow it to your own subdomain. |
| `DEMO_USER` / `DEMO_PASSWORD` | Credentials shown on the sign-in page. |
| `PRIVATE_KEY_PEM` | Optional RSA private key (PKCS#8 PEM, `\n` escaped). Without it a new key is generated on every start, which invalidates existing tokens. |

MCPCore only talks to HTTPS on port 443. While testing locally, expose the server with a tunnel such as `cloudflared tunnel --url http://localhost:4000` and use the tunnel URL as `ISSUER`.

## Connect it to MCPCore

1. Create or edit your server in the MCPCore dashboard and choose **OAuth 2.0** in the Security step.
2. Paste the metadata URL: `https://<your-issuer>/.well-known/oauth-authorization-server`.
3. Save. Connect any MCP client (Claude, Codex, Cursor, MCP Inspector). The client discovers this server, registers itself, opens the sign-in page and receives a token.

## Test with MCP Inspector

```bash
npx @modelcontextprotocol/inspector
```

Choose **Streamable HTTP**, enter `https://<subdomain>.mcpcore.io/mcp` and click **Connect**. Inspector walks through discovery, registration, sign-in and token exchange.
