const axios = require('axios');

const apiConfig = {
    baseURL: 'http://localhost:8200/v1',
    timeout: 2000,
    maxContentLength: 65536,
    validateStatus: () => true
};

module.exports = {
    api: axios.create(apiConfig),

    withToken(token) {
        return {headers: {'X-Vault-Token': token}};
    }
};
