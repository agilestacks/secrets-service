/* eslint-disable prefer-destructuring */
const crypto = require('crypto');
const axios = require('axios');
const httpAdapter = require('axios/lib/adapters/http');
const uuidv4 = require('uuid/v4');

// eslint-disable-next-line import/no-unresolved
const vaultServiceRoles = require('../vault-service-roles.json');

const apiPrefix = '/api/v1';
const apiConfig = {
    baseURL: 'http://localhost:3002',
    adapter: httpAdapter,
    timeout: 3000,
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

const apiV1open = axios.create({...apiConfig, ...withApiPrefix});

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
        const config = {...apiConfig, ...withApiPrefix};

        apiV1serviceHigh = axios.create({...config, ...withToken(tokenHigh)});
        apiV1serviceLow = axios.create({...config, ...withToken(tokenLow)});
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

    test('environments no access', async () => {
        expect.assertions(4);

        const path = '/users/okta-4';

        const putResp = await apiV1serviceHigh.put(path);
        expect(putResp.status).toBe(201);
        expect(putResp.data.roleId).toBeDefined();

        const environments = {environments: []};
        const envPutResp = await apiV1serviceHigh.put(`${path}/environments`, environments);
        expect(envPutResp.status).toBe(204);

        const deleteResp = await apiV1serviceHigh.delete(path);
        expect(deleteResp.status).toBe(204);
    });

    test('cloud-accounts', async () => {
        expect.assertions(4);

        const path = '/users/okta-5';

        const putResp = await apiV1serviceHigh.put(path);
        expect(putResp.status).toBe(201);
        expect(putResp.data.roleId).toBeDefined();

        const cloudAccounts = {cloudAccounts: ['clacc-1', 'clacc-2']};
        const envPutResp = await apiV1serviceHigh.put(`${path}/cloud-accounts`, cloudAccounts);
        expect(envPutResp.status).toBe(204);

        const deleteResp = await apiV1serviceHigh.delete(path);
        expect(deleteResp.status).toBe(204);
    });

    test('cloud-accounts no access', async () => {
        expect.assertions(4);

        const path = '/users/okta-6';

        const putResp = await apiV1serviceHigh.put(path);
        expect(putResp.status).toBe(201);
        expect(putResp.data.roleId).toBeDefined();

        const cloudAccounts = {cloudAccounts: []};
        const envPutResp = await apiV1serviceHigh.put(`${path}/cloud-accounts`, cloudAccounts);
        expect(envPutResp.status).toBe(204);

        const deleteResp = await apiV1serviceHigh.delete(path);
        expect(deleteResp.status).toBe(204);
    });

    test('environments for non-existent', async () => {
        expect.assertions(1);

        const path = '/users/okta-7';

        const environments = {environments: []};
        const envPutResp = await apiV1serviceHigh.put(`${path}/environments`, environments);
        expect(envPutResp.status).toBe(404);
    });

    test('cloud-accounts for non-existent', async () => {
        expect.assertions(1);

        const path = '/users/okta-8';

        const cloudAccounts = {cloudAccounts: []};
        const envPutResp = await apiV1serviceHigh.put(`${path}/cloud-accounts`, cloudAccounts);
        expect(envPutResp.status).toBe(404);
    });

    test('login', async () => {
        expect.assertions(6);

        const path = '/users/okta-9';

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

    const paths = ['/secrets/environments/env-1', '/secrets/cloud-accounts/clacc-1'];
    const secretTemplate = add => ({
        name: 'component.postgresql.password',
        kind: 'password',
        username: 'automation-hub',
        password: `jai0eite3X${add}`
    });

    const setupApi = async () => {
        const loginResp = await apiV1open.post(authServiceLoginPath,
            serviceRoles(vaultServiceRoles.highPrivAuth, vaultServiceRoles.lowPrivAuth));
        const tokenHigh = loginResp.data.highPrivToken;
        const tokenLow = loginResp.data.lowPrivToken;
        const config = {...apiConfig, ...withApiPrefix};

        apiV1serviceHigh = axios.create({...config, ...withToken(tokenHigh)});
        apiV1serviceLow = axios.create({...config, ...withToken(tokenLow)});

        const user = `/users/okta-${randomSuf()}`;
        const putResp = await apiV1serviceHigh.put(user);
        const roleId = putResp.data.roleId;
        await apiV1serviceHigh.put(`${user}/environments`, {environments: ['env-1']});
        await apiV1serviceHigh.put(`${user}/cloud-accounts`, {cloudAccounts: ['clacc-1']});
        const userLoginResp = await apiV1serviceLow.post(`${user}/login`, {roleId});
        const tokenUser = userLoginResp.data.token;

        apiV1user = axios.create({...config, ...withToken(tokenUser)});
    };

    beforeAll(setupApi);

    test('create, get, update, delete - password', () => {
        expect.assertions(24);

        return Promise.all(paths.map(async (path) => {
            const secret = secretTemplate(path);

            const postResp = await apiV1user.post(path, secret);
            expect(postResp.status).toBe(201);
            expect(postResp.headers.location).toBeDefined();
            expect(postResp.data.id).toBeDefined();

            const id = postResp.data.id;
            const location = postResp.headers.location;
            expect(location).toBe(`${apiPrefix}${path}/${id}`);

            const getResp = await apiV1user.get(`${path}/${id}`);
            expect(getResp.status).toBe(200);
            expect(getResp.data).toEqual({...secret, ...{id}});

            secret.username = 'something-else';
            const putResp = await apiV1user.put(`${path}/${id}`, secret);
            expect(putResp.status).toBe(204);

            const get2Resp = await apiV1user.get(`${path}/${id}`);
            expect(get2Resp.status).toBe(200);
            expect(get2Resp.data).toEqual({...secret, ...{id}});

            secret.kind = 'text';
            const put2Resp = await apiV1user.put(`${path}/${id}`, secret);
            expect(put2Resp.status).toBe(409);

            const deleteResp = await apiV1user.delete(`${path}/${id}`);
            expect(deleteResp.status).toBe(204);

            const getNoneResp = await apiV1user.get(`${path}/${id}`);
            expect(getNoneResp.status).toBe(404);
        }));
    });

    test('create with id', () => {
        expect.assertions(12);

        return Promise.all(paths.map(async (path) => {
            const secret = secretTemplate(path);

            const id = uuidv4();

            const putResp = await apiV1user.put(`${path}/${id}`, secret);
            expect(putResp.status).toBe(404);

            const put2Resp = await apiV1user.put(`${path}/${id}?create=1`, secret);
            expect(put2Resp.status).toBe(201);

            const getResp = await apiV1user.get(`${path}/${id}`);
            expect(getResp.status).toBe(200);
            expect(getResp.data).toEqual({...secret, ...{id}});

            const deleteResp = await apiV1user.delete(`${path}/${id}`);
            expect(deleteResp.status).toBe(204);

            const getNoneResp = await apiV1user.get(`${path}/${id}`);
            expect(getNoneResp.status).toBe(404);
        }));
    });

    test('create by example', () => {
        expect.assertions(30);

        return Promise.all(paths.map(async (path) => {
            const secret = secretTemplate(path);
            // create first secret
            const postResp = await apiV1user.post(path, secret);
            expect(postResp.status).toBe(201);
            expect(postResp.headers.location).toBeDefined();
            expect(postResp.data.id).toBeDefined();

            const id = postResp.data.id;
            const location = postResp.headers.location;
            expect(location).toBe(`${apiPrefix}${path}/${id}`);

            // create second secret by copying first secret
            const fromPath = `${path}/${id}`.replace(/^\/secrets\//, '');
            const patch = {username: 'secrets-service'};
            const post2Resp = await apiV1user.post(`${path}/copy/${fromPath}`, patch);
            expect(post2Resp.status).toBe(201);
            expect(post2Resp.headers.location).toBeDefined();
            expect(post2Resp.data.id).toBeDefined();

            const copyId = post2Resp.data.id;
            const location2 = post2Resp.headers.location;
            expect(location2).toBe(`${apiPrefix}${path}/${copyId}`);

            // request second secret and compare
            const getResp = await apiV1user.get(`${path}/${copyId}`);
            expect(getResp.status).toBe(200);
            expect(getResp.data).toEqual({...secret, ...patch, ...{id: copyId}});

            // attempt to create third secret with incompatible `kind`
            const post3Resp = await apiV1user.post(`${path}/copy/${fromPath}`, {kind: 'privateKey'});
            expect(post3Resp.status).toBe(409);

            // delete secrets
            const deleteResp = await apiV1user.delete(`${path}/${id}`);
            expect(deleteResp.status).toBe(204);
            const delete2Resp = await apiV1user.delete(`${path}/${copyId}`);
            expect(delete2Resp.status).toBe(204);

            const getNoneResp = await apiV1user.get(`${path}/${id}`);
            expect(getNoneResp.status).toBe(404);
            const getNone2Resp = await apiV1user.get(`${path}/${copyId}`);
            expect(getNone2Resp.status).toBe(404);
        }));
    });

    test('delete all', () => {
        expect.assertions(22);

        return Promise.all(paths.map(async (path) => {
            const ids = [uuidv4(), uuidv4(), `${uuidv4()}:${uuidv4()}`];
            const putResponses = await Promise.all(
                ids.map(id => apiV1user.put(`${path}/${id}?create=1`, secretTemplate(`${path}/${id}`)))
            );
            putResponses.forEach(resp => expect(resp.status).toBe(201));

            const getResponses = await Promise.all(
                ids.map(id => apiV1user.get(`${path}/${id}`))
            );
            getResponses.forEach(resp => expect(resp.status).toBe(200));

            const deleteAllResp = await apiV1user.delete(path);
            expect(deleteAllResp.status).toBe(204);
            const deleteAll2Resp = await apiV1user.delete(path);
            expect(deleteAll2Resp.status).toBe(404);

            const getNoneResponses = await Promise.all(
                ids.map(id => apiV1user.get(`${path}/${id}`))
            );
            getNoneResponses.forEach(resp => expect(resp.status).toBe(404));
        }));
    });

    // TODO `cloudAccount` is only for /cloud-accounts
    test('cloud account - mask', () => {
        expect.assertions(30);

        return Promise.all(paths.map(async (path) => {
            const secret = {
                name: 'customer.account',
                kind: 'cloudAccount',
                cloud: 'aws',
                roleArn: 'arn:aws:iam::973998981304:role/lambda_basic_execution',
                externalId: '4f606425________________________________',
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
            expect(getResp.data.externalId).toBe('4f606425********************************');
            expect(getResp.data.accessKey).toBe('AKIAJWMT************');
            expect(getResp.data.secretKey).toBe('3SaI************************************');

            const deleteResp = await apiV1user.delete(`${path}/${id}`);
            expect(deleteResp.status).toBe(204);

            const getNoneResp = await apiV1user.get(`${path}/${id}`);
            expect(getNoneResp.status).toBe(404);
        }));
    });

    test('session token - role', () => {
        expect.assertions(24);

        return Promise.all(paths.map(async (path) => {
            const secret = {
                name: 'customer.role',
                kind: 'cloudAccount',
                cloud: 'aws',
                roleArn: 'arn:aws:iam::973998981304:role/secrets-service-test-role',
                duration: 1234
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
            expect(keysResp.data.ttl).toBe(secret.duration);

            const deleteResp = await apiV1user.delete(`${path}/${id}`);
            expect(deleteResp.status).toBe(204);

            const getNoneResp = await apiV1user.get(`${path}/${id}`);
            expect(getNoneResp.status).toBe(404);
        }));
    });

    test.skip('session token - keys', () => {
        expect.assertions(24);

        return Promise.all(paths.map(async (path) => {
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
        }));
    });

    // hope it is the last test to execute
    test('renew, revoke - token', async () => {
        const renewResp = await apiV1user.post('/tokens/renew');
        expect(renewResp.status).toBe(200);
        expect(renewResp.data.ttl).toBe(7200);

        const revokeResp = await apiV1user.post('/tokens/revoke');
        expect(revokeResp.status).toBe(204);

        const renewRevokedResp = await apiV1user.post('/tokens/renew');
        expect(renewRevokedResp.status).toBe(403);
    });
});
