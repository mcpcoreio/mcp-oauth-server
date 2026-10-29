require("dotenv").config({quiet: true});

const trimTrailingSlash = (value) => String(value || "").replace(/\/+$/, "");

const config = {
    port: Number(process.env.PORT || 4000),
    issuer: trimTrailingSlash(process.env.ISSUER || `http://localhost:${process.env.PORT || 4000}`),
    resourcePattern: new RegExp(process.env.RESOURCE_PATTERN || "^https://[a-z0-9-]+\\.mcpcore\\.io/mcp$"),
    demoUser: process.env.DEMO_USER || "demo@example.com",
    demoPassword: process.env.DEMO_PASSWORD || "",
    accessTokenTtlSeconds: Number(process.env.ACCESS_TOKEN_TTL_SECONDS || 3600),
    refreshTokenTtlSeconds: Number(process.env.REFRESH_TOKEN_TTL_SECONDS || 2592000),
    authorizationCodeTtlSeconds: 60,
    privateKeyPem: process.env.PRIVATE_KEY_PEM ? process.env.PRIVATE_KEY_PEM.replace(/\\n/g, "\n") : null,
    supportedScopes: ["mcp:read", "mcp:write"],
};

if (!config.demoPassword) {
    throw new Error("DEMO_PASSWORD must be set. Copy .env.example to .env and choose a password.");
}

module.exports = config;
