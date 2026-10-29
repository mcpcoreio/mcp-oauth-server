const config = require("../helper/config");
const {
    saveClient,
    saveAuthorizationCode,
    consumeAuthorizationCode,
    saveRefreshToken,
    consumeRefreshToken,
} = require("../helper/store");
const {
    createRandomToken,
    getJwks,
    signAccessToken,
    verifyPkce,
    normalizeScope,
    escapeHtml,
    buildRedirectUrl,
    sendOAuthError,
    safeEqual,
} = require("../helper/functions");

function metadata(req, res) {
    return res.json({
        issuer: config.issuer,
        authorization_endpoint: `${config.issuer}/authorize`,
        token_endpoint: `${config.issuer}/token`,
        registration_endpoint: `${config.issuer}/register`,
        jwks_uri: `${config.issuer}/jwks`,
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code", "refresh_token"],
        code_challenge_methods_supported: ["S256"],
        token_endpoint_auth_methods_supported: ["none"],
        scopes_supported: config.supportedScopes,
        authorization_response_iss_parameter_supported: true,
    });
}

function jwks(req, res) {
    return res.set("Cache-Control", "public, max-age=300").json(getJwks());
}

function register(req, res) {
    const client = saveClient({
        clientId: createRandomToken(16),
        clientName: req.data.clientName,
        redirectUris: req.data.redirectUris,
        createdAt: Math.floor(Date.now() / 1000),
    });

    return res.status(201).set("Cache-Control", "no-store").json({
        client_id: client.clientId,
        client_id_issued_at: client.createdAt,
        client_name: client.clientName,
        redirect_uris: client.redirectUris,
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        token_endpoint_auth_method: "none",
        scope: normalizeScope(req.data.scope),
    });
}

function renderLoginPage({client, redirectUri, codeChallenge, state, scope, resource}, errorMessage = "") {
    const hiddenFields = {
        response_type: "code",
        client_id: client.clientId,
        redirect_uri: redirectUri,
        code_challenge: codeChallenge,
        code_challenge_method: "S256",
        state,
        scope,
        resource,
    };

    return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in</title>
<style>
body{font-family:system-ui,sans-serif;background:#f4f4f5;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}
form{background:#fff;padding:32px;border-radius:16px;width:320px;box-shadow:0 10px 30px rgba(0,0,0,.08);display:flex;flex-direction:column;gap:12px}
input{padding:10px 12px;border:1px solid #d4d4d8;border-radius:10px;font-size:14px}
button{padding:10px;border:0;border-radius:10px;background:#0485f7;color:#fff;font-weight:600;cursor:pointer}
p{margin:0;font-size:13px;color:#71717a}.error{color:#dc2626}
</style>
</head>
<body>
<form method="post" action="/authorize">
<h2 style="margin:0">Sign in</h2>
<p><strong>${escapeHtml(client.clientName)}</strong> wants to access <code>${escapeHtml(resource)}</code></p>
${errorMessage ? `<p class="error">${escapeHtml(errorMessage)}</p>` : ""}
${Object.entries(hiddenFields).map(([key, value]) => `<input type="hidden" name="${key}" value="${escapeHtml(value)}">`).join("\n")}
<input name="username" type="email" placeholder="Email" autocomplete="username" required>
<input name="password" type="password" placeholder="Password" autocomplete="current-password" required>
<button type="submit">Allow access</button>
</form>
</body>
</html>`;
}

function showAuthorize(req, res) {
    return res.set("Cache-Control", "no-store").send(renderLoginPage(req.data));
}

function approveAuthorize(req, res) {
    const isValidUser = safeEqual(req.body.username, config.demoUser) && safeEqual(req.body.password, config.demoPassword);

    if (!isValidUser) {
        return res.status(401).set("Cache-Control", "no-store").send(renderLoginPage(req.data, "Invalid email or password."));
    }

    const code = createRandomToken();

    saveAuthorizationCode(code, {
        clientId: req.data.client.clientId,
        redirectUri: req.data.redirectUri,
        codeChallenge: req.data.codeChallenge,
        scope: normalizeScope(req.data.scope),
        resource: req.data.resource,
        subject: config.demoUser,
        expiresAt: Date.now() + config.authorizationCodeTtlSeconds * 1000,
    });

    return res.redirect(302, buildRedirectUrl(req.data.redirectUri, {code, state: req.data.state, iss: config.issuer}));
}

function issueTokens(res, {clientId, subject, scope, resource}) {
    const refreshToken = createRandomToken();

    saveRefreshToken(refreshToken, {
        clientId,
        subject,
        scope,
        resource,
        expiresAt: Date.now() + config.refreshTokenTtlSeconds * 1000,
    });

    return res.set("Cache-Control", "no-store").json({
        access_token: signAccessToken({subject, audience: resource, clientId, scope}),
        token_type: "Bearer",
        expires_in: config.accessTokenTtlSeconds,
        refresh_token: refreshToken,
        scope,
    });
}

function token(req, res) {
    const {client, grantType} = req.data;

    if (grantType === "authorization_code") {
        const authorizationCode = consumeAuthorizationCode(req.body.code);

        if (!authorizationCode || authorizationCode.clientId !== client.clientId || authorizationCode.redirectUri !== req.body.redirect_uri) {
            return sendOAuthError(res, "invalid_grant", "The authorization code is invalid or expired.");
        }

        if (!verifyPkce(req.body.code_verifier, authorizationCode.codeChallenge)) {
            return sendOAuthError(res, "invalid_grant", "PKCE verification failed.");
        }

        if (req.body.resource && req.body.resource !== authorizationCode.resource) {
            return sendOAuthError(res, "invalid_target", "resource does not match the authorization request.");
        }

        return issueTokens(res, authorizationCode);
    }

    const storedRefreshToken = consumeRefreshToken(req.body.refresh_token);

    if (!storedRefreshToken || storedRefreshToken.clientId !== client.clientId) {
        return sendOAuthError(res, "invalid_grant", "The refresh token is invalid or expired.");
    }

    if (req.body.resource && req.body.resource !== storedRefreshToken.resource) {
        return sendOAuthError(res, "invalid_target", "resource does not match the original grant.");
    }

    return issueTokens(res, storedRefreshToken);
}

module.exports = {
    metadata,
    jwks,
    register,
    showAuthorize,
    approveAuthorize,
    token,
};
