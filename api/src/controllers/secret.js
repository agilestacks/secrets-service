const {v4: uuidv4} = require('uuid');
const {pick: lopick, isEmpty, partition} = require('lodash');
const {allowedEntities, allowedFields, checkEntityKind, checkSecretKind, checkCloudKind} = require('../validate');
const {maskSecrets} = require('../mask');
const {awsSession, awsSessionVia, azureSession, gcpSession} = require('../cloud');
const {api, withToken, goodStatus, proxyErrorStatus} = require('../vault');
const {logger} = require('../logger');
const {NotFoundError, BadRequestError, ForbiddenError, ServerError} = require('../errors');

const stubSecrets = new Map();

module.exports = {
    allowedEntities,
    checkEntityKind,

    async create(ctx) {
        const {
            params: {entityId, entityKind},
            request: {body}
        } = ctx;

        checkEntityKind(entityKind);
        const secret = lopick(body, allowedFields);
        checkSecretKind(secret.kind);
        checkCloudKind(secret);
        const id = uuidv4();
        if (entityId.startsWith('stub-')) {
            stubSecrets.set(id, secret);
        } else {
            const path = `/secret/${entityKind}/${entityId}/secrets/${id}`;
            const resp = await api.put(path, secret, withToken(ctx.vaultToken));
            if (resp.status !== 204) {
                logger.warn('Unexpected status %d from Vault creating secret `%s` / `%s`: %j',
                    resp.status, path, secret.name, resp.data);
                ctx.status = proxyErrorStatus(resp);
                return;
            }
        }
        ctx.status = 201;
        ctx.set('Location', `${ctx.path}/${id}`);
        ctx.body = {id};
    },

    async update(ctx) {
        const {
            params: {id, entityId, entityKind},
            query: {create},
            request: {body}
        } = ctx;

        checkEntityKind(entityKind);
        const update = lopick(body, allowedFields);
        checkSecretKind(update.kind);
        checkCloudKind(update);
        if (entityId.startsWith('stub-')) {
            const secret = stubSecrets.get(id);
            if (secret) {
                if (secret.kind === update.kind) {
                    stubSecrets.set(id, update);
                    ctx.status = 204;
                } else {
                    throw new BadRequestError('Conflict', 409);
                }
            } else {
                throw new NotFoundError();
            }
        } else {
            const wvt = withToken(ctx.vaultToken);
            const path = `/secret/${entityKind}/${entityId}/secrets/${id.replace(':', '/')}`;
            const getResp = await api.get(path, wvt);
            if (getResp.status !== 200) {
                if (getResp.status === 404) {
                    if (!create) {
                        throw new NotFoundError();
                    }
                } else {
                    logger.warn('Unexpected status %d from Vault reading secret `%s`: %j',
                        getResp.status, path, getResp.data);
                    ctx.status = proxyErrorStatus(getResp);
                }
            }
            const updating = getResp.status === 200;
            if (updating) {
                // First .data is axios response field. Second .data is Vault payload field.
                const secret = getResp.data.data;
                if (secret.kind !== update.kind) {
                    const msg = 'Secret `kind` doesn\'t match';
                    logger.error(msg, {oldKind: secret.kind, newKind: update.kind});
                    throw new BadRequestError(msg, 409);
                }
                if (secret.cloud && secret.cloud !== update.cloud) {
                    const msg = 'Secret `cloud` doesn\'t match';
                    logger.error(msg, {oldCloud: secret.cloud, newCloud: update.cloud});
                    throw new BadRequestError(msg, 409);
                }
            }
            const putResp = await api.put(path, update, wvt);
            if (putResp.status !== 204) {
                logger.warn('Unexpected status %d from Vault %s secret `%s` / `%s`: %j',
                    putResp.status, updating ? 'updating' : 'creating', path, update.name, putResp.data);
                ctx.status = proxyErrorStatus(putResp);
            } else {
                ctx.status = updating ? 204 : 201;
            }
        }
    },

    async delete(ctx) {
        const {
            params: {id, entityId, entityKind}
        } = ctx;

        checkEntityKind(entityKind);
        if (entityId.startsWith('stub-')) {
            const removed = stubSecrets.delete(id);
            if (removed) {
                ctx.status = 204;
            } else {
                throw new NotFoundError();
            }
        } else {
            const wvt = withToken(ctx.vaultToken);
            const path = `/secret/${entityKind}/${entityId}/secrets/${id.replace(':', '/')}`;
            const resp = await api.delete(path, wvt);
            if (resp.status !== 204) {
                if (resp.status === 404) {
                    throw new NotFoundError();
                } else {
                    logger.warn('Unexpected status %d from Vault deleting secret `%s`: %j',
                        resp.status, path, resp.data);
                    ctx.status = proxyErrorStatus(resp);
                }
            } else {
                ctx.status = 204;
            }
        }
    },

    async deleteAll(ctx) {
        const {
            params: {entityId, entityKind}
        } = ctx;

        checkEntityKind(entityKind);
        if (entityId.startsWith('stub-')) {
            ctx.status = 204;
        } else {
            const wvt = withToken(ctx.vaultToken);
            const root = `/secret/${entityKind}/${entityId}/secrets`;

            let errorStatus;
            const recurse = async (subpath) => {
                const path = `${root}/${subpath}`;
                const resp = await api.get(`${path}?list=true`, wvt);
                if (resp.status !== 200) {
                    if (resp.status !== 404) {
                        logger.warn('Unexpected status %d from Vault listing secrets under `%s`: %j',
                            resp.status, path, resp.data);
                        errorStatus = proxyErrorStatus(resp);
                    }
                    return [];
                }
                const {data: {keys}} = resp.data;
                if (isEmpty(keys)) {
                    logger.debug('No secrets to delete under `%s`', path);
                    return [];
                }
                const [subtrees, leafs] = partition(keys, key => key.endsWith('/'));
                return leafs.concat(
                    ...(await Promise.all(subtrees.map(key => recurse(`${subpath}${key}`)))))
                    .map(key => `${subpath}${key}`);
            };

            const keys = await recurse('');
            if (isEmpty(keys)) {
                ctx.status = errorStatus || 404;
                return;
            }
            const responses = await Promise.all(keys.map(key => api.delete(`${root}/${key}`, wvt)));
            responses.filter(resp => resp.status !== 204)
                .forEach(({status, config: {url}, data}) => logger
                    .warn('Unexpected status %d from Vault deleting secret `%s`: %j', status, url, data)
                );
            ctx.status = goodStatus(...responses) ? 204 : proxyErrorStatus(...responses);
        }
    },

    async get(ctx) {
        const {
            params: {id, entityId, entityKind},
            query: {unmask}
        } = ctx;

        checkEntityKind(entityKind);
        if (entityId.startsWith('stub-')) {
            const secret = stubSecrets.get(id);
            if (secret) {
                ctx.status = 200;
                ctx.body = {...secret, ...{id}};
            } else {
                throw new NotFoundError();
            }
        } else {
            const wvt = withToken(ctx.vaultToken);
            const path = `/secret/${entityKind}/${entityId}/secrets/${id.replace(':', '/')}`;
            const resp = await api.get(path, wvt);
            if (resp.status !== 200) {
                if (resp.status === 404) {
                    throw new NotFoundError();
                } else {
                    logger.warn('Unexpected status %d from Vault reading secret `%s`: %j',
                        resp.status, path, resp.data);
                    ctx.status = proxyErrorStatus(resp);
                }
            } else {
                ctx.status = 200;
                let secret = resp.data.data;
                if (!unmask) {
                    secret = maskSecrets(secret);
                }
                ctx.body = {...secret, ...{id}};
            }
        }
    },

    async createFrom(ctx) {
        const {
            params: {entityId, entityKind, fromEntityId, fromEntityKind, fromId},
            request: {body}
        } = ctx;

        checkEntityKind(entityKind);
        checkEntityKind(fromEntityKind);
        const patch = lopick(body, allowedFields);
        if (patch.kind) {
            checkSecretKind(patch.kind);
            checkCloudKind(patch); // if `kind=cloud` is presented, then `cloud` must be set
        }

        let fromSecret;
        if (fromEntityId.startsWith('stub-')) {
            fromSecret = stubSecrets.get(fromId);
            if (!fromSecret) {
                throw new NotFoundError();
            }
        } else {
            const wvt = withToken(ctx.vaultToken);
            const path = `/secret/${fromEntityKind}/${fromEntityId}/secrets/${fromId}`;
            const resp = await api.get(path, wvt);
            if (resp.status !== 200) {
                if (resp.status === 404) {
                    throw new NotFoundError();
                } else {
                    logger.warn('Unexpected status %d from Vault reading secret `%s`: %j',
                        resp.status, path, resp.data);
                    ctx.status = proxyErrorStatus(resp);
                    return;
                }
            } else {
                fromSecret = resp.data.data;
            }
        }

        if (patch.kind && patch.kind !== fromSecret.kind) {
            const msg = 'Secret `kind` doesn\'t match';
            logger.error(msg, {oldKind: fromSecret.kind, newKind: patch.kind});
            throw new BadRequestError(msg, 409);
        }
        if (patch.cloud && patch.cloud !== fromSecret.cloud) {
            const msg = 'Secret `cloud` doesn\'t match';
            logger.error(msg, {oldCloud: fromSecret.cloud, newCloud: patch.cloud});
            throw new BadRequestError(msg, 409);
        }

        // TODO is there a better way?
        const fromPath = `/copy/${fromEntityKind}/${fromEntityId}/${fromId}`;
        if (!ctx.path.endsWith(fromPath)) {
            throw new ServerError(`Expected ${ctx.path} to end with ${fromPath}`);
        }
        const resourceBase = ctx.path.substring(0, ctx.path.length - fromPath.length);

        const secret = {...fromSecret, ...patch};

        const id = uuidv4();
        if (entityId.startsWith('stub-')) {
            stubSecrets.set(id, secret);
        } else {
            const path = `/secret/${entityKind}/${entityId}/secrets/${id}`;
            const resp = await api.put(path, secret, withToken(ctx.vaultToken));
            if (resp.status !== 204) {
                logger.warn('Unexpected status %d from Vault creating secret `%s` / `%s`: %j',
                    resp.status, path, secret.name, resp.data);
                ctx.status = proxyErrorStatus(resp);
                return;
            }
        }
        ctx.status = 201;
        ctx.set('Location', `${resourceBase}/${id}`);
        ctx.body = {id};
    },

    async sessionKeys(ctx) {
        const {
            params: {id, entityId, entityKind,
                viaId, viaEntityId, viaEntityKind},
            request: {body}
        } = ctx;

        checkEntityKind(entityKind);
        if (entityId.startsWith('stub-')) {
            const secret = stubSecrets.get(id);
            if (secret) {
                checkCloudKind(secret, true);
                ctx.status = 200;
                ctx.body = {
                    cloud: 'aws',
                    accessKey: 'AKIA****************',
                    secretKey: 'IqCFm0**********************************',
                    sessionToken: '...',
                    ttl: secret.duration || 3600
                };
            } else {
                throw new NotFoundError();
            }
        } else {
            const path = `/secret/${entityKind}/${entityId}/secrets/${id}`;
            const resp = await api.get(path, withToken(ctx.vaultToken));
            if (resp.status !== 200) {
                if (resp.status === 404) {
                    throw new NotFoundError();
                } else {
                    logger.warn('Unexpected status %d from Vault reading secret `%s`: %j',
                        resp.status, path, resp.data);
                    ctx.status = proxyErrorStatus(resp);
                }
            } else {
                const secret = resp.data.data;
                checkCloudKind(secret, true);
                let session;
                if (viaId) {
                    if (secret.cloud !== 'aws') {
                        throw new BadRequestError(
                            `Secret 'cloud' must be 'aws' to call '/via' resoure; got '${secret.cloud}'`,
                            405);
                    }
                    if (!ctx.viaVaultToken) {
                        throw new ForbiddenError();
                    }
                    const viaPath = `/secret/${viaEntityKind}/${viaEntityId}/secrets/${viaId}`;
                    const viaResp = await api.get(viaPath, withToken(ctx.viaVaultToken));
                    if (viaResp.status !== 200) {
                        if (viaResp.status === 404) {
                            throw new NotFoundError();
                        } else {
                            logger.warn('Unexpected status %d from Vault reading secret `%s`: %j',
                                viaResp.status, viaPath, viaResp.data);
                            ctx.status = proxyErrorStatus(viaResp);
                            return;
                        }
                    }
                    const viaSecret = viaResp.data.data;
                    checkCloudKind(viaSecret, true);
                    if (viaSecret.cloud !== 'aws') {
                        throw new BadRequestError(
                            `Via secret 'cloud' must be 'aws' to call under '/via' resoure; got '${secret.cloud}'`,
                            405);
                    }
                    session = await awsSessionVia(secret, viaSecret, body);
                } else {
                    switch (secret.cloud) {
                    case 'aws':
                        session = await awsSession(secret, body);
                        break;
                    case 'azure':
                        session = azureSession(secret);
                        break;
                    case 'gcp':
                        session = gcpSession(secret);
                        break;
                    default:
                    }
                }
                ctx.status = 200;
                ctx.body = {cloud: secret.cloud, ...session};
            }
        }
    }
};
