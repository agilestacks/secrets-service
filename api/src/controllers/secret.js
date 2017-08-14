const crypto = require('crypto');
const aws = require('aws-sdk');
const awsConfig = require('aws-config');
const uuidv4 = require('uuid/v4');
const {pick: lopick} = require('lodash');
const {api, withToken, proxyErrorStatus} = require('../vault');
const {logger} = require('../logger');

aws.config = awsConfig();
const sts = new aws.STS();
const stsTtl = 3600;

const secrets = new Map();

let apiPrefix = '';

const allowedKinds = ['password', 'cloudAccount'];
const allowedFields = [
    'name', 'kind',
    'username', 'password',
    'cloud', 'accessKey', 'secretKey', 'roleArn'
];

const randomSuf = () => crypto.randomBytes(3).toString('hex');

// util.promisify() won't work on AWS SDK functions
function assumeRole(roleName, purpose) {
    const prefix = purpose.substring(0, 57).replace(/[^\w+=,.@-]/g, '-');
    const params = {
        RoleArn: roleName,
        RoleSessionName: `${prefix}-${randomSuf()}`, // max length is 64
        DurationSeconds: stsTtl
    };
    return new Promise((resolve, reject) => {
        sts.assumeRole(params, (err, data) => {
            if (err) reject(err);
            else resolve(data);
        });
    });
}

function getSession(accessKeyId, secretAccessKey) {
    const accountSts = new aws.STS(awsConfig({accessKeyId, secretAccessKey}));
    const params = {
        DurationSeconds: stsTtl
    };
    return new Promise((resolve, reject) => {
        accountSts.getSessionToken(params, (err, data) => {
            if (err) reject(err);
            else resolve(data);
        });
    });
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

function maskKey(key) {
    const truncAt = key.startsWith('AKIA') ? 8 : 4;
    return key.substring(0, truncAt).padEnd(key.length, '*');
}

function maskSecret(secret) {
    const masked = Object.assign({}, secret);
    if (secret.kind === 'cloudAccount' && secret.cloud === 'aws') {
        if (masked.roleArn) masked.roleArn = maskRole(secret.roleArn);
        if (masked.accessKey) masked.accessKey = maskKey(masked.accessKey);
        if (masked.secretKey) masked.secretKey = maskKey(masked.secretKey);
    }
    return masked;
}

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
                ctx.status = proxyErrorStatus(resp);
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
                    ctx.status = proxyErrorStatus(getResp);
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
                        ctx.status = proxyErrorStatus(putResp);
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
                    ctx.status = proxyErrorStatus(resp);
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
                    ctx.status = proxyErrorStatus(resp);
                }
            } else {
                ctx.status = 200;
                ctx.body = Object.assign({}, maskSecret(resp.data.data), {id});
            }
        }
    },

    async sessionKeys(ctx) {
        const id = ctx.params.id;
        const envId = ctx.params.environmentId;
        if (envId.startsWith('stub-')) {
            const secret = secrets.get(id);
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
                    ctx.status = 405;
                    ctx.body = {
                        error: 'The requested secret is not `cloudAccount` kind'
                    };
                }
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
                    ctx.status = proxyErrorStatus(resp);
                }
            } else {
                const secret = resp.data.data;
                if (secret.kind === 'cloudAccount' && secret.cloud === 'aws') {
                    let promise;
                    if (secret.roleArn) {
                        const purpose = (ctx.request.body && ctx.request.body.purpose) ?
                            ctx.request.body.purpose :
                            'automation';
                        promise = assumeRole(secret.roleArn, purpose);
                    } else if (secret.accessKey && secret.secretKey) {
                        promise = getSession(secret.accessKey, secret.secretKey);
                    } else {
                        ctx.status = 405;
                        ctx.body = {
                            error: 'The requested secret has no `roleArn`, nor `accessKey` with `secretKey` defined'
                        };
                        return;
                    }
                    // eslint-disable-next-line consistent-return
                    return promise
                        .then((stsReply) => {
                            const creds = stsReply.Credentials;
                            ctx.status = 200;
                            ctx.body = {
                                cloud: 'aws',
                                accessKey: creds.AccessKeyId,
                                secretKey: creds.SecretAccessKey,
                                sessionToken: creds.SessionToken,
                                ttl: stsTtl
                            };
                        })
                        .catch((err) => {
                            ctx.status = 502;
                            ctx.body = {
                                error: secret.roleArn ?
                                    `AWS STS error assuming role '${maskRole(secret.roleArn)}': ${err}` :
                                    `AWS STS error opening session for '${maskKey(secret.accessKey)}': ${err}`
                            };
                        });
                // eslint-disable-next-line no-else-return
                } else {
                    ctx.status = 405;
                    ctx.body = {
                        error: 'The requested secret is not `cloudAccount:aws` kind'
                    };
                }
            }
        }
    }
};
