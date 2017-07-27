const uuidv4 = require('uuid/v4');
const {pick: lopick} = require('lodash');
const {api, withToken} = require('../vault');
const {logger} = require('../logger');

const secrets = new Map();

let apiPrefix = '';

const allowedKinds = ['password', 'cloudAccount'];
const allowedFields = [
    'name', 'kind',
    'username', 'password',
    'cloud', 'accessKey', 'secretKey', 'roleArn'
];

module.exports = {
    setApiPrefix(prefix) {
        apiPrefix = prefix;
    },

    async create(ctx) {
        const envId = ctx.params.environmentId;
        const secret = lopick(ctx.request.body, allowedFields);
        if (!allowedKinds.some(kind => kind === secret.kind)) {
            ctx.status = 400;
            ctx.body = {error: `Secret 'kind' must be one of '${allowedKinds.join(', ')}'; got '${secret.kind}'`};
            return;
        }
        const id = uuidv4();
        if (envId.startsWith('stub-')) {
            secrets.set(id, secret);
        } else {
            const path = `/secret/environments/${envId}/secrets/${id}`;
            const resp = await api.put(path, secret, withToken(ctx.vaultToken));
            if (resp.status !== 204) {
                logger.warn('Unexpected status %d from Vault creating secret `%s` / `%s`: %j',
                    resp.status, path, secret.name, resp.data);
                ctx.status = resp.status === 403 ? 403 : 502;
                return;
            }
        }
        ctx.status = 201;
        ctx.set('Location', `${apiPrefix}/environments/${envId}/secrets/${id}`);
        ctx.body = {id};
    },

    async update(ctx) {
        const id = ctx.params.id;
        const envId = ctx.params.environmentId;
        const update = lopick(ctx.request.body, allowedFields);
        if (!allowedKinds.some(kind => kind === update.kind)) {
            ctx.status = 400;
            ctx.body = {error: `Secret 'kind' must be one of '${allowedKinds.join(', ')}'; got '${update.kind}'`};
            return;
        }
        if (envId.startsWith('stub-')) {
            const secret = secrets.get(id);
            if (secret) {
                if (secret.kind === update.kind) {
                    secrets.set(id, update);
                    ctx.status = 204;
                } else {
                    ctx.status = 409;
                }
            } else {
                ctx.status = 404;
            }
        } else {
            const path = `/secret/environments/${envId}/secrets/${id}`;
            const getResp = await api.get(path, withToken(ctx.vaultToken));
            if (getResp.status !== 200) {
                if (getResp.status === 404) {
                    ctx.status = 404;
                } else {
                    logger.warn('Unexpected status %d from Vault reading secret `%s`: %j',
                        getResp.status, path, getResp.data);
                    ctx.status = getResp.status === 403 ? 403 : 502;
                }
            } else {
                const secret = getResp.data;
                if (secret.kind !== update.kind) {
                    ctx.status = 409;
                    ctx.body = {error: 'Secret `kind` doesn\'t match'};
                } else {
                    const putResp = await api.put(path, update, withToken(ctx.vaultToken));
                    if (putResp.status !== 204) {
                        logger.warn('Unexpected status %d from Vault updating secret `%s` / `%s`: %j',
                            putResp.status, path, update.name, putResp.data);
                        ctx.status = putResp.status === 403 ? 403 : 502;
                    } else {
                        ctx.status = 204;
                    }
                }
            }
        }
    },

    async delete(ctx) {
        const id = ctx.params.id;
        const envId = ctx.params.environmentId;
        if (envId.startsWith('stub-')) {
            ctx.status = secrets.delete(id) ? 204 : 404;
        } else {
            const path = `/secret/environments/${envId}/secrets/${id}`;
            const resp = await api.delete(path, withToken(ctx.vaultToken));
            if (resp.status !== 204) {
                if (resp.status === 404) {
                    ctx.status = 404;
                } else {
                    logger.warn('Unexpected status %d from Vault deleting secret `%s`: %j',
                        resp.status, path, resp.data);
                    ctx.status = resp.status === 403 ? 403 : 502;
                }
            } else {
                ctx.status = 204;
            }
        }
    },

    async get(ctx) {
        const id = ctx.params.id;
        const envId = ctx.params.environmentId;
        if (envId.startsWith('stub-')) {
            const secret = secrets.get(id);
            if (secret) {
                ctx.status = 200;
                ctx.body = Object.assign({}, secret, {id});
            } else {
                ctx.status = 404;
            }
        } else {
            const path = `/secret/environments/${envId}/secrets/${id}`;
            const resp = await api.get(path, withToken(ctx.vaultToken));
            if (resp.status !== 200) {
                if (resp.status === 404) {
                    ctx.status = 404;
                } else {
                    logger.warn('Unexpected status %d from Vault reading secret `%s`: %j',
                        resp.status, path, resp.data);
                    ctx.status = resp.status === 403 ? 403 : 502;
                }
            } else {
                ctx.status = 200;
                ctx.body = Object.assign({}, resp.data.data, {id});
            }
        }
    },

    sessionKeys(ctx) {
        const id = ctx.params.id;
        const secret = secrets.get(id);
        if (secret) {
            ctx.status = 200;
            ctx.body = {
                cloud: 'aws',
                accessKey: 'AKIA****************',
                secretKey: 'IqCFm0**********************************',
                sessionToken: '...'
            };
        } else {
            ctx.status = 404;
        }
    }
};
