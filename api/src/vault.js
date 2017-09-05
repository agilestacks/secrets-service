const axios = require('axios');

const apiConfig = {
    baseURL: process.env.VAULT_API || 'http://localhost:8200/v1',
    timeout: 10000,
    maxContentLength: 65536,
    validateStatus: () => true
};

module.exports = {
    api: axios.create(apiConfig),

    withToken(token) {
        return {headers: {'X-Vault-Token': token}};
    },

    goodStatus(response) {
        return [200, 201, 204].some(good => good === response.status);
    },

    proxyErrorStatus(response) {
        return response.status === 403 || response.status === 404 ? response.status : 502;
    }
};
