const crypto = require('crypto');
const axios = require('axios');
const httpAdapter = require('axios/lib/adapters/http');

// eslint-disable-next-line import/no-unresolved
const vaultServiceRoles = require('../vault-service-roles.json');

const apiPrefix = '/api/v1';
const apiConfig = {
    baseURL: 'http://localhost:3002',
    adapter: httpAdapter,
    timeout: 2000,
    maxContentLength: 65536,
    validateStatus: () => true
};
const withApiPrefix = {baseURL: `${apiConfig.baseURL}${apiPrefix}`};
const withToken = (token) => {
    const headers = {headers: {'X-Secrets-Token': token}};
    return headers;
};
const authServiceLoginPath = '/apps/authentication-service/login';
const serviceRoles = (highPrivRoleId, lowPrivRoleId) => {
    const roles = {highPrivRoleId, lowPrivRoleId};
    return roles;
};
const randomSuf = () => crypto.randomBytes(3).toString('hex');

const apiV1open = axios.create(Object.assign({}, apiConfig, withApiPrefix));

describe('basic routing', () => {
    test('ping', async () => {
        expect.assertions(2);

        const getResp = await apiV1open.get('/ping');
        expect(getResp.status).toBe(200);
        expect(getResp.data).toBe('pong');
    });

    test('version', async () => {
        expect.assertions(2);

        const getResp = await apiV1open.get('/version');
        expect(getResp.status).toBe(200);
        expect(getResp.data.rev).toBeDefined();
    });
});

describe('app service roles', () => {
    test('login', async () => {
        expect.assertions(4);

        const loginResp = await apiV1open.post(authServiceLoginPath,
            serviceRoles(vaultServiceRoles.highPrivAuth, vaultServiceRoles.lowPrivAuth));
        expect(loginResp.status).toBe(200);
        expect(loginResp.data.highPrivToken).toBeDefined();
        expect(loginResp.data.lowPrivToken).toBeDefined();
        expect(loginResp.data.ttl).toBeDefined();
    });
});

describe('users', () => {
    let apiV1serviceHigh;
    let apiV1serviceLow;

    const setupApi = async () => {
        const loginResp = await apiV1open.post(authServiceLoginPath,
            serviceRoles(vaultServiceRoles.highPrivAuth, vaultServiceRoles.lowPrivAuth));
        const tokenHigh = loginResp.data.highPrivToken;
        const tokenLow = loginResp.data.lowPrivToken;
        const config = Object.assign({}, apiConfig, withApiPrefix);

        apiV1serviceHigh = axios.create(Object.assign({}, config, withToken(tokenHigh)));
        apiV1serviceLow = axios.create(Object.assign({}, config, withToken(tokenLow)));
    };

    beforeAll(setupApi);

    test('create & delete', async () => {
        expect.assertions(3);

        const path = '/users/okta-1';

        const putResp = await apiV1serviceHigh.put(path);
        expect(putResp.status).toBe(201);
        expect(putResp.data.roleId).toBeDefined();

        const deleteResp = await apiV1serviceHigh.delete(path);
        expect(deleteResp.status).toBe(204);
    });

    test('delete non-existent', async () => {
        expect.assertions(1);

        const path = '/users/okta-2';

        const deleteResp = await apiV1serviceHigh.delete(path);
        expect(deleteResp.status).toBe(404);
    });

    test('environments', async () => {
        expect.assertions(4);

        const path = '/users/okta-3';

        const putResp = await apiV1serviceHigh.put(path);
        expect(putResp.status).toBe(201);
        expect(putResp.data.roleId).toBeDefined();

        const environments = {environments: ['env-1', 'env-2']};
        const envPutResp = await apiV1serviceHigh.put(`${path}/environments`, environments);
        expect(envPutResp.status).toBe(204);

        const deleteResp = await apiV1serviceHigh.delete(path);
        expect(deleteResp.status).toBe(204);
    });

    test('environments for non-existent', async () => {
        expect.assertions(1);

        const path = '/users/okta-4';

        const environments = {environments: []};
        const envPutResp = await apiV1serviceHigh.put(`${path}/environments`, environments);
        expect(envPutResp.status).toBe(404);
    });

    test('login', async () => {
        expect.assertions(6);

        const path = '/users/okta-5';

        const putResp = await apiV1serviceHigh.put(path);
        expect(putResp.status).toBe(201);
        expect(putResp.data.roleId).toBeDefined();

        const roleId = putResp.data.roleId;

        const loginResp = await apiV1serviceLow.post(`${path}/login`, {roleId});
        expect(loginResp.status).toBe(200);
        expect(loginResp.data.token).toBeDefined();
        expect(loginResp.data.ttl).toBeDefined();

        const deleteResp = await apiV1serviceHigh.delete(path);
        expect(deleteResp.status).toBe(204);
    });
});

describe('secrets', () => {
    let apiV1serviceHigh;
    let apiV1serviceLow;
    let apiV1user;

    const setupApi = async () => {
        const loginResp = await apiV1open.post(authServiceLoginPath,
            serviceRoles(vaultServiceRoles.highPrivAuth, vaultServiceRoles.lowPrivAuth));
        const tokenHigh = loginResp.data.highPrivToken;
        const tokenLow = loginResp.data.lowPrivToken;
        const config = Object.assign({}, apiConfig, withApiPrefix);

        apiV1serviceHigh = axios.create(Object.assign({}, config, withToken(tokenHigh)));
        apiV1serviceLow = axios.create(Object.assign({}, config, withToken(tokenLow)));

        const user = `/users/okta-${randomSuf()}`;
        const putResp = await apiV1serviceHigh.put(user);
        const roleId = putResp.data.roleId;
        // eslint-disable-next-line no-unused-vars
        const putEnvResp = await apiV1serviceHigh.put(`${user}/environments`, {environments: ['env-1']});
        const userLoginResp = await apiV1serviceLow.post(`${user}/login`, {roleId});
        const tokenUser = userLoginResp.data.token;

        apiV1user = axios.create(Object.assign({}, config, withToken(tokenUser)));
    };

    beforeAll(setupApi);

    test('create, get, update, delete - password', async () => {
        expect.assertions(8);

        const path = '/environments/env-1/secrets';
        const secret = {
            name: 'component.postgresql.password',
            kind: 'password',
            username: 'automation-hub',
            password: 'jai0eite3X'
        };

        const postResp = await apiV1user.post(path, secret);
        expect(postResp.status).toBe(201);
        expect(postResp.headers.location).toBeDefined();
        expect(postResp.data.id).toBeDefined();

        const id = postResp.data.id;
        const location = postResp.headers.location;
        expect(location).toBe(`${apiPrefix}${path}/${id}`);

        const getResp = await apiV1user.get(`${path}/${id}`);
        expect(getResp.status).toBe(200);
        expect(getResp.data).toEqual(Object.assign({}, secret, {id}));

        const deleteResp = await apiV1user.delete(`${path}/${id}`);
        expect(deleteResp.status).toBe(204);

        const getNoneResp = await apiV1user.get(`${path}/${id}`);
        expect(getNoneResp.status).toBe(404);
    });

    test('cloud account - mask', async () => {
        expect.assertions(14);

        const path = '/environments/env-1/secrets';
        const secret = {
            name: 'customer.account',
            kind: 'cloudAccount',
            cloud: 'aws',
            roleArn: 'arn:aws:iam::973998981304:role/lambda_basic_execution',
            accessKey: 'AKIAJWMTY___________',
            secretKey: '3SaIOZR1________________________________'
        };

        const postResp = await apiV1user.post(path, secret);
        expect(postResp.status).toBe(201);
        expect(postResp.headers.location).toBeDefined();
        expect(postResp.data.id).toBeDefined();

        const id = postResp.data.id;
        const location = postResp.headers.location;
        expect(location).toBe(`${apiPrefix}${path}/${id}`);

        const getResp = await apiV1user.get(`${path}/${id}`);
        expect(getResp.status).toBe(200);
        expect(getResp.data.id).toBe(id);
        expect(getResp.data.name).toBe(secret.name);
        expect(getResp.data.kind).toBe(secret.kind);
        expect(getResp.data.cloud).toBe(secret.cloud);
        expect(getResp.data.roleArn).toBe('arn:aws:iam::973998981304:role/lamb******************');
        expect(getResp.data.accessKey).toBe('AKIAJWMT************');
        expect(getResp.data.secretKey).toBe('3SaI************************************');

        const deleteResp = await apiV1user.delete(`${path}/${id}`);
        expect(deleteResp.status).toBe(204);

        const getNoneResp = await apiV1user.get(`${path}/${id}`);
        expect(getNoneResp.status).toBe(404);
    });

    test('session token - role', async () => {
        expect.assertions(12);

        const path = '/environments/env-1/secrets';
        const secret = {
            name: 'customer.role',
            kind: 'cloudAccount',
            cloud: 'aws',
            roleArn: 'arn:aws:iam::973998981304:role/lambda_basic_execution'
        };

        const postResp = await apiV1user.post(path, secret);
        expect(postResp.status).toBe(201);
        expect(postResp.headers.location).toBeDefined();
        expect(postResp.data.id).toBeDefined();

        const id = postResp.data.id;
        const location = postResp.headers.location;
        expect(location).toBe(`${apiPrefix}${path}/${id}`);

        const keysResp = await apiV1user.post(`${path}/${id}/session-keys`,
            {purpose: 'secrets service test'});
        expect(keysResp.status).toBe(200);
        expect(keysResp.data.cloud).toBeDefined();
        expect(keysResp.data.accessKey).toBeDefined();
        expect(keysResp.data.secretKey).toBeDefined();
        expect(keysResp.data.sessionToken).toBeDefined();
        expect(keysResp.data.ttl).toBeDefined();

        const deleteResp = await apiV1user.delete(`${path}/${id}`);
        expect(deleteResp.status).toBe(204);

        const getNoneResp = await apiV1user.get(`${path}/${id}`);
        expect(getNoneResp.status).toBe(404);
    });

    test.skip('session token - keys', async () => {
        expect.assertions(12);

        const path = '/environments/env-1/secrets';
        const secret = {
            name: 'customer.keys',
            kind: 'cloudAccount',
            cloud: 'aws',
            accessKey: '',
            secretKey: ''
        };

        const postResp = await apiV1user.post(path, secret);
        expect(postResp.status).toBe(201);
        expect(postResp.headers.location).toBeDefined();
        expect(postResp.data.id).toBeDefined();

        const id = postResp.data.id;
        const location = postResp.headers.location;
        expect(location).toBe(`${apiPrefix}${path}/${id}`);

        const keysResp = await apiV1user.post(`${path}/${id}/session-keys`,
            {purpose: 'secrets service test'});
        expect(keysResp.status).toBe(200);
        expect(keysResp.data.cloud).toBeDefined();
        expect(keysResp.data.accessKey).toBeDefined();
        expect(keysResp.data.secretKey).toBeDefined();
        expect(keysResp.data.sessionToken).toBeDefined();
        expect(keysResp.data.ttl).toBeDefined();

        const deleteResp = await apiV1user.delete(`${path}/${id}`);
        expect(deleteResp.status).toBe(204);

        const getNoneResp = await apiV1user.get(`${path}/${id}`);
        expect(getNoneResp.status).toBe(404);
    });

    // hope it is the last test to execute
    test('renew, revoke - token', async () => {
        const renewResp = await apiV1user.post('/tokens/renew');
        expect(renewResp.status).toBe(200);
        expect(renewResp.data.ttl).toBe(3600);

        const revokeResp = await apiV1user.post('/tokens/revoke');
        expect(revokeResp.status).toBe(204);

        const renewRevokedResp = await apiV1user.post('/tokens/renew');
        expect(renewRevokedResp.status).toBe(403);
    });
});
