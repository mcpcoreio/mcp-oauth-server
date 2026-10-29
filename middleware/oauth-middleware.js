const {findClient} = require("../helper/store");
const {isAllowedRedirectUri, isAllowedResource, sendOAuthError} = require("../helper/functions");

function allowCors(req, res, next) {
    res.set("Access-Control-Allow-Origin", "*");
    res.set("Access-Control-Allow-Headers", "Content-Type, Authorization, MCP-Protocol-Version");
    res.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");

    if (req.method === "OPTIONS") {
        return res.sendStatus(204);
    }

    return next();
}

function validateRegistration(req, res, next) {
    const redirectUris = req.body?.redirect_uris;

    if (!Array.isArray(redirectUris) || redirectUris.length === 0) {
        return sendOAuthError(res, "invalid_redirect_uri", "redirect_uris must be a non-empty array.");
    }

    if (!redirectUris.every(isAllowedRedirectUri)) {
        return sendOAuthError(res, "invalid_redirect_uri", "Every redirect URI must use HTTPS, a loopback HTTP address or a private-use scheme.");
    }

    const authMethod = req.body?.token_endpoint_auth_method ?? "none";

    if (authMethod !== "none") {
        return sendOAuthError(res, "invalid_client_metadata", "Only public clients (token_endpoint_auth_method=none) are supported.");
    }

    req.data = {
        redirectUris,
        clientName: String(req.body?.client_name || "MCP Client").slice(0, 100),
        scope: req.body?.scope,
    };

    return next();
}

function validateAuthorizationRequest(req, res, next) {
    const params = req.method === "GET" ? req.query : req.body;
    const client = findClient(String(params.client_id || ""));

    if (!client) {
        return res.status(400).send("Unknown client_id. Register the client first.");
    }

    if (!client.redirectUris.includes(params.redirect_uri)) {
        return res.status(400).send("redirect_uri does not match a registered redirect URI.");
    }

    const redirectError = (error, description) => res.redirect(302, `${params.redirect_uri}${params.redirect_uri.includes("?") ? "&" : "?"}${new URLSearchParams({
        error,
        error_description: description,
        ...(params.state ? {state: params.state} : {}),
    })}`);

    if (params.response_type !== "code") {
        return redirectError("unsupported_response_type", "Only response_type=code is supported.");
    }

    if (!params.code_challenge || params.code_challenge_method !== "S256") {
        return redirectError("invalid_request", "PKCE with code_challenge_method=S256 is required.");
    }

    if (!isAllowedResource(params.resource)) {
        return redirectError("invalid_target", "The resource parameter is missing or not allowed.");
    }

    req.data = {
        client,
        redirectUri: params.redirect_uri,
        codeChallenge: params.code_challenge,
        state: params.state || "",
        scope: params.scope || "",
        resource: params.resource,
    };

    return next();
}

function validateTokenRequest(req, res, next) {
    const grantType = req.body?.grant_type;
    const client = findClient(String(req.body?.client_id || ""));

    if (!client) {
        return sendOAuthError(res, "invalid_client", "Unknown client_id.", 401);
    }

    if (grantType === "authorization_code") {
        if (!req.body.code || !req.body.redirect_uri || !req.body.code_verifier) {
            return sendOAuthError(res, "invalid_request", "code, redirect_uri and code_verifier are required.");
        }
    } else if (grantType === "refresh_token") {
        if (!req.body.refresh_token) {
            return sendOAuthError(res, "invalid_request", "refresh_token is required.");
        }
    } else {
        return sendOAuthError(res, "unsupported_grant_type", "Use authorization_code or refresh_token.");
    }

    if (req.body.resource && !isAllowedResource(req.body.resource)) {
        return sendOAuthError(res, "invalid_target", "The resource parameter is not allowed.");
    }

    req.data = {client, grantType};

    return next();
}

module.exports = {
    allowCors,
    validateRegistration,
    validateAuthorizationRequest,
    validateTokenRequest,
};
