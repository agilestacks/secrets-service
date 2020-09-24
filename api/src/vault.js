const axios = require('axios');

const apiConfig = {
    baseURL: process.env.VAULT_API || 'http://localhost:8200/v1',
    timeout: 20000,
    maxContentLength: 65536,
    validateStatus: () => true
};

module.exports = {
    api: axios.create(apiConfig),

    withToken(token) {
        return {headers: {'X-Vault-Token': token}};
    },

    goodStatus(...responses) {
        return responses.every(response => [200, 201, 204].some(good => good === response.status));
    },

    proxyErrorStatus(...responses) {
        const http40x = r => r.status === 403 || r.status === 404;
        return responses.some(http40x) ? responses.find(http40x).status : 502;
    },

    printBadResponses(print, format, id, ...responses) {
        responses.filter(r => !module.exports.goodStatus(r)).forEach(r => print(format, r.status, id, r.data));
    }
};
