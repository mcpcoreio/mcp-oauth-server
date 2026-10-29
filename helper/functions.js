const crypto = require("crypto");
const config = require("./config");

const signingKey = config.privateKeyPem
    ? crypto.createPrivateKey(config.privateKeyPem)
    : crypto.generateKeyPairSync("rsa", {modulusLength: 2048}).privateKey;

const publicJwk = crypto.createPublicKey(signingKey).export({format: "jwk"});
const keyId = crypto.createHash("sha256").update(JSON.stringify(publicJwk)).digest("base64url").slice(0, 16);

const toBase64Url = (value) => Buffer.from(typeof value === "string" ? value : JSON.stringify(value)).toString("base64url");

function createRandomToken(byteLength = 32) {
    return crypto.randomBytes(byteLength).toString("base64url");
}

function getJwks() {
    return {
        keys: [{...publicJwk, kid: keyId, use: "sig", alg: "RS256"}],
    };
}

function signAccessToken({subject, audience, clientId, scope}) {
    const issuedAt = Math.floor(Date.now() / 1000);
    const header = {alg: "RS256", typ: "at+jwt", kid: keyId};
    const payload = {
        iss: config.issuer,
        sub: subject,
        aud: audience,
        client_id: clientId,
        scope,
        iat: issuedAt,
        exp: issuedAt + config.accessTokenTtlSeconds,
        jti: createRandomToken(16),
    };
    const signingInput = `${toBase64Url(header)}.${toBase64Url(payload)}`;
    const signature = crypto.sign("RSA-SHA256", Buffer.from(signingInput), signingKey).toString("base64url");

    return `${signingInput}.${signature}`;
}

function verifyPkce(codeVerifier, codeChallenge) {
    if (!/^[A-Za-z0-9._~-]{43,128}$/.test(String(codeVerifier || ""))) {
        return false;
    }

    const expected = Buffer.from(crypto.createHash("sha256").update(codeVerifier).digest("base64url"));
    const received = Buffer.from(String(codeChallenge || ""));

    return expected.length === received.length && crypto.timingSafeEqual(expected, received);
}

const BLOCKED_REDIRECT_PROTOCOLS = ["javascript:", "data:", "file:", "vbscript:"];
const LOOPBACK_HOSTS = ["localhost", "127.0.0.1", "[::1]"];

function isAllowedRedirectUri(value) {
    try {
        const url = new URL(value);

        if (url.hash || BLOCKED_REDIRECT_PROTOCOLS.includes(url.protocol)) {
            return false;
        }

        if (url.protocol === "http:") {
            return LOOPBACK_HOSTS.includes(url.hostname);
        }

        return true;
    } catch {
        return false;
    }
}

function normalizeScope(scope) {
    const requested = String(scope || "").split(" ").filter(Boolean);
    const granted = requested.filter((item) => config.supportedScopes.includes(item));

    return (granted.length > 0 ? granted : config.supportedScopes).join(" ");
}

function isAllowedResource(resource) {
    return typeof resource === "string" && config.resourcePattern.test(resource);
}

function escapeHtml(value) {
    return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

function buildRedirectUrl(redirectUri, params) {
    const url = new URL(redirectUri);

    Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined && value !== null && value !== "") {
            url.searchParams.set(key, value);
        }
    });

    return url.toString();
}

function sendOAuthError(res, error, description, status = 400) {
    return res.status(status).set("Cache-Control", "no-store").json({error, error_description: description});
}

function safeEqual(first, second) {
    const firstBuffer = Buffer.from(String(first ?? ""));
    const secondBuffer = Buffer.from(String(second ?? ""));

    return firstBuffer.length === secondBuffer.length && crypto.timingSafeEqual(firstBuffer, secondBuffer);
}

module.exports = {
    createRandomToken,
    getJwks,
    signAccessToken,
    verifyPkce,
    isAllowedRedirectUri,
    normalizeScope,
    isAllowedResource,
    escapeHtml,
    buildRedirectUrl,
    sendOAuthError,
    safeEqual,
};
