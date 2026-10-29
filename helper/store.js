const clients = new Map();
const authorizationCodes = new Map();
const refreshTokens = new Map();

const isExpired = (record) => !record || record.expiresAt <= Date.now();

function saveClient(client) {
    clients.set(client.clientId, client);
    return client;
}

function findClient(clientId) {
    return clients.get(clientId) ?? null;
}

function saveAuthorizationCode(code, record) {
    authorizationCodes.set(code, record);
}

function consumeAuthorizationCode(code) {
    const record = authorizationCodes.get(code);
    authorizationCodes.delete(code);

    return isExpired(record) ? null : record;
}

function saveRefreshToken(token, record) {
    refreshTokens.set(token, record);
}

function consumeRefreshToken(token) {
    const record = refreshTokens.get(token);
    refreshTokens.delete(token);

    return isExpired(record) ? null : record;
}

module.exports = {
    saveClient,
    findClient,
    saveAuthorizationCode,
    consumeAuthorizationCode,
    saveRefreshToken,
    consumeRefreshToken,
};
