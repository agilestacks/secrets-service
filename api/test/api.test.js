const axios = require('axios');
const httpAdapter = require('axios/lib/adapters/http');

const apiPrefix = '/api/v1';
const apiConfig = {
    baseURL: 'http://localhost:3002',
    adapter: httpAdapter,
    timeout: 2000,
    maxContentLength: 65536,
    headers: {
        'X-Secrets-Token': 'qwerty'
    }
};
const apiV1 = axios.create(Object.assign({}, apiConfig, {
    baseURL: `${apiConfig.baseURL}${apiPrefix}`
}));

describe('routing', () => {
    test('ping', async () => {
        expect.assertions(2);

        const getResp = await apiV1.get('/ping');
        expect(getResp.status).toBe(200);
        expect(getResp.data).toBe('pong');
    });

    test('version', async () => {
        expect.assertions(2);

        const getResp = await apiV1.get('/version');
        expect(getResp.status).toBe(200);
        expect(getResp.data.rev).toBeDefined();
    });
});
