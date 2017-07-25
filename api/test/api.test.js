const crypto = require('crypto');
const axios = require('axios');
const httpAdapter = require('axios/lib/adapters/http');

const serviceRoleHighPrivAuth = 'role-stub-high-priv-auth';
const serviceRoleLowPrivAuth = 'role-stub-low-priv-auth';
// const serviceRoleHighPrivHub = 'role-stub-high-priv-hub';
// const serviceRoleLowPrivHub = 'role-stub-low-priv-hub';

const apiPrefix = '/api/v1';
const apiConfig = {
    baseURL: 'http://localhost:3002',
    adapter: httpAdapter,
    timeout: 2000,
    maxContentLength: 65536
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

describe('service roles', () => {
    test('login', async () => {
        expect.assertions(4);

        const loginResp = await apiV1open.post(authServiceLoginPath,
            serviceRoles(serviceRoleHighPrivAuth, serviceRoleLowPrivAuth));
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
            serviceRoles(serviceRoleHighPrivAuth, serviceRoleLowPrivAuth));
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

        const putResp = await apiV1serviceLow.put(path);
        expect(putResp.status).toBe(201);
        expect(putResp.data.roleId).toBeDefined();

        const roleId = putResp.data.roleId;

        const loginResp = await apiV1serviceLow.post(`${path}/login`, {roleId});
        expect(loginResp.status).toBe(200);
        expect(loginResp.data.token).toBeDefined();
        expect(loginResp.data.ttl).toBeDefined();

        const deleteResp = await apiV1serviceLow.delete(path);
        expect(deleteResp.status).toBe(204);
    });
});

describe('secrets', () => {
    let apiV1serviceHigh;
    let apiV1serviceLow;
    let apiV1user;

    const setupApi = async () => {
        const loginResp = await apiV1open.post(authServiceLoginPath,
            serviceRoles(serviceRoleHighPrivAuth, serviceRoleLowPrivAuth));
        const tokenHigh = loginResp.data.highPrivToken;
        const tokenLow = loginResp.data.lowPrivToken;
        const config = Object.assign({}, apiConfig, withApiPrefix);

        apiV1serviceHigh = axios.create(Object.assign({}, config, withToken(tokenHigh)));
        apiV1serviceLow = axios.create(Object.assign({}, config, withToken(tokenLow)));

        const user = `/users/okta-${randomSuf()}`;
        const putResp = await apiV1serviceHigh.put(user);
        const roleId = putResp.data.roleId;
        const userLoginResp = await apiV1serviceLow.post(`${user}/login`, {roleId});
        const tokenUser = userLoginResp.data.token;

        apiV1user = axios.create(Object.assign({}, config, withToken(tokenUser)));
    };

    beforeAll(setupApi);

    test('create & delete', async () => {
        expect.assertions(3);

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
        expect(location).toBe(`${withApiPrefix}/${path}/${id}`);

        const deleteResp = await apiV1user.delete(`${path}/${id}`);
        expect(deleteResp.status).toBe(204);
    });
});
