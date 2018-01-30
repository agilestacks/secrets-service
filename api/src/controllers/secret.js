const crypto = require('crypto');
const aws = require('aws-sdk');
const awsConfig = require('aws-config');
const uuidv4 = require('uuid/v4');
const {pick: lopick} = require('lodash');
const {api, withToken, proxyErrorStatus} = require('../vault');
const {logger} = require('../logger');
const {NotFoundError, BadRequestError, ServerError} = require('../errors');

aws.config = awsConfig();
const sts = new aws.STS();
const stsTtl = 3600;

const stubSecrets = new Map();

const allowedEntities = ['environments', 'cloud-accounts', 'licenses', 'templates', 'instances', 'service-accounts'];
const allowedKinds = [
    'password', 'cloudAccount', 'cloudAccessKeys', 'caPrivateKey',
    'certificate', 'sshKey', 'usernamePassword', 'text', 'license',
    'loginToken'
];
const allowedFields = [
    'name', 'kind',
    'username', 'password', 'loginToken', 'licenseKey',
    'certificate', 'sshKey', 'caPrivateKey', 'text',
    'cloud', 'accessKey', 'secretKey', 'roleArn', 'externalId'
];

const randomSuf = () => crypto.randomBytes(3).toString('hex');

function assumeRole(roleName, externalId, purpose) {
    const prefix = purpose.substring(0, 57).replace(/[^\w+=,.@-]/g, '-');
    const params = {
        RoleArn: roleName,
        ExternalId: externalId,
        RoleSessionName: `${prefix}-${randomSuf()}`, // max length is 64
        DurationSeconds: stsTtl
    };
    return sts.assumeRole(params).promise();
}

function getSession(accessKeyId, secretAccessKey) {
    const accountSts = new aws.STS(awsConfig({accessKeyId, secretAccessKey}));
    const params = {
        DurationSeconds: stsTtl
    };
    return accountSts.getSessionToken(params).promise();
}

function maskRole(roleArn) {
    const c = roleArn.split(':', 6);
    if (c.length >= 6) {
        const roleName = c[5];
        c[5] = roleName.substring(0, 9).padEnd(roleName.length, '*');
        return c.join(':');
    }
    return roleArn.substring(0, 26).padEnd(roleArn.length, '*');
}

function maskExternalId(externalId) {
    const truncAt = Math.min(externalId.length, 10) - 2;
    return externalId.substr(0, truncAt).padEnd(externalId.length, '*');
}

function maskKey(key) {
    const truncAt = key.startsWith('AK') ? 8 : 4;
    return key.substring(0, truncAt).padEnd(key.length, '*');
}

function maskSecret(secret) {
    const masked = Object.assign({}, secret);
    if (secret.kind === 'cloudAccount' && secret.cloud === 'aws') {
        if (masked.roleArn) masked.roleArn = maskRole(secret.roleArn);
        if (masked.externalId) masked.externalId = maskExternalId(masked.externalId);
        if (masked.accessKey) masked.accessKey = maskKey(masked.accessKey);
        if (masked.secretKey) masked.secretKey = maskKey(masked.secretKey);
    }
    return masked;
}

function checkEntityKind(entity) {
    if (!allowedEntities.some(kind => kind === entity)) {
        const error = `Entity must be one of '${allowedEntities.join(', ')}'; got '${entity}'`;
        throw new BadRequestError(error);
    }
}

function checkSecretKind(secret) {
    if (!allowedKinds.some(kind => kind === secret)) {
        const error = `Secret 'kind' must be one of '${allowedKinds.join(', ')}'; got '${secret}'`;
        throw new BadRequestError(error);
    }
}

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
            request: {body}
        } = ctx;

        checkEntityKind(entityKind);
        const update = lopick(body, allowedFields);
        checkSecretKind(update.kind);
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
            const path = `/secret/${entityKind}/${entityId}/secrets/${id}`;
            const getResp = await api.get(path, wvt);
            if (getResp.status !== 200) {
                if (getResp.status === 404) {
                    throw new NotFoundError();
                } else {
                    logger.warn('Unexpected status %d from Vault reading secret `%s`: %j',
                        getResp.status, path, getResp.data);
                    ctx.status = proxyErrorStatus(getResp);
                }
            } else {
                // First .data is axios response field. Second .data is Vault payload field.
                const secret = getResp.data.data;
                if (secret.kind !== update.kind) {
                    const msg = 'Secret `kind` doesn\'t match';
                    logger.error(msg, {oldKind: secret.kind, newKind: update.kind});
                    throw new BadRequestError(msg, 409);
                } else {
                    const putResp = await api.put(path, update, wvt);
                    if (putResp.status !== 204) {
                        logger.warn('Unexpected status %d from Vault updating secret `%s` / `%s`: %j',
                            putResp.status, path, update.name, putResp.data);
                        ctx.status = proxyErrorStatus(putResp);
                    } else {
                        ctx.status = 204;
                    }
                }
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
            const path = `/secret/${entityKind}/${entityId}/secrets/${id}`;
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

    async get(ctx) {
        const {
            params: {id, entityId, entityKind}
        } = ctx;

        checkEntityKind(entityKind);
        if (entityId.startsWith('stub-')) {
            const secret = stubSecrets.get(id);
            if (secret) {
                ctx.status = 200;
                ctx.body = Object.assign({}, secret, {id});
            } else {
                throw new NotFoundError();
            }
        } else {
            const wvt = withToken(ctx.vaultToken);
            const path = `/secret/${entityKind}/${entityId}/secrets/${id}`;
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
                ctx.body = Object.assign({}, maskSecret(resp.data.data), {id});
            }
        }
    },

    async sessionKeys(ctx) {
        const {
            params: {id, entityId, entityKind},
            request: {body}
        } = ctx;

        checkEntityKind(entityKind);
        if (entityId.startsWith('stub-')) {
            const secret = stubSecrets.get(id);
            if (secret) {
                if (secret.kind === 'cloudAccount') {
                    ctx.status = 200;
                    ctx.body = {
                        cloud: 'aws',
                        accessKey: 'AKIA****************',
                        secretKey: 'IqCFm0**********************************',
                        sessionToken: '...'
                    };
                } else {
                    throw new BadRequestError('The requested secret is not `cloudAccount` kind', 405);
                }
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
                if (secret.kind === 'cloudAccount' && secret.cloud === 'aws') {
                    let stsReply;
                    if (secret.roleArn) {
                        const purpose = (body && body.purpose)
                            ? body.purpose
                            : 'automation';
                        try {
                            stsReply = await assumeRole(secret.roleArn, secret.externalId, purpose);
                        } catch (err) {
                            throw new ServerError(
                                `AWS STS error assuming role '${maskRole(secret.roleArn)}': ${err}`,
                                {status: 502}
                            );
                        }
                    } else if (secret.accessKey && secret.secretKey) {
                        try {
                            stsReply = await getSession(secret.accessKey, secret.secretKey);
                        } catch (err) {
                            throw new ServerError(
                                `AWS STS error opening session for '${maskKey(secret.accessKey)}': ${err}`,
                                {status: 502}
                            );
                        }
                    } else {
                        throw new BadRequestError(
                            'The requested secret has no `roleArn`, nor `accessKey` with `secretKey` defined',
                            405
                        );
                    }

                    const creds = stsReply.Credentials;
                    ctx.status = 200;
                    ctx.body = {
                        cloud: 'aws',
                        accessKey: creds.AccessKeyId,
                        secretKey: creds.SecretAccessKey,
                        sessionToken: creds.SessionToken,
                        ttl: stsTtl
                    };
                } else {
                    throw new BadRequestError(
                        'The requested secret is not `cloudAccount:aws` kind',
                        405
                    );
                }
            }
        }
    }
};
