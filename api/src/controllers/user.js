const {camelCase} = require('lodash');
const {api, withToken, goodStatus, proxyErrorStatus, printBadResponses} = require('../vault');
const {logger} = require('../logger');
const {NotFoundError, BadRequestError} = require('../errors');

const stubUsers = new Map(); // Jest tests

const environmentPolicyFragment = `
path "secret/environments/{{id}}/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
`;

const cloudAccountPolicyFragment = `
path "secret/cloud-accounts/{{id}}/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
`;

const tokenPolicy = `
path "auth/token/renew-self" {
  capabilities = ["update"]
}

path "auth/token/revoke-self" {
  capabilities = ["update"]
}
`;

async function updatePolicy(ctx, entity, template) {
    const id = ctx.params.id;
    const entityCamelCase = camelCase(entity);
    const list = ctx.request.body[entityCamelCase];
    if (list) {
        if (id.startsWith('stub-')) {
            const user = stubUsers.get(id);
            if (user) {
                ctx.status = 204;
            } else {
                throw new NotFoundError();
            }
        } else {
            const wvt = withToken(ctx.vaultToken);
            const policyPath = `/sys/policy/${id}-${entity}`;
            const policyResp = await api.get(policyPath, wvt);
            if (policyResp.status === 200) {
                const policyRules = list.map(eId => template.replace('{{id}}', eId)).join('\n');
                const policyPutResp = await api.put(policyPath, {rules: policyRules || '#'}, wvt);
                if (goodStatus(policyPutResp)) {
                    ctx.status = 204;
                } else {
                    logger.warn('Unexpected status %d from Vault while updating policy `%s-%s`: %j',
                        policyResp.status, id, entity, policyPutResp.data);
                    ctx.status = proxyErrorStatus(policyPutResp);
                }
            } else {
                ctx.status = policyResp.status;
            }
        }
    } else {
        throw new BadRequestError(`'${entityCamelCase}' field is not set`);
    }
}

module.exports = {
    async create(ctx) {
        const id = ctx.params.id;
        if (id.startsWith('stub-')) {
            const roleId = 'f2db06c7-1b3c-9262-1116-fa1842a5c567';
            const user = {id, roleId};
            stubUsers.set(id, user);
            ctx.status = 201;
            ctx.body = {roleId};
        } else if (!id.startsWith('okta-')) {
            throw new BadRequestError(`User id must start with okta-, got ${id}`);
        } else {
            const wvt = withToken(ctx.vaultToken);
            const tokenPolicyResp = await api.put(`/sys/policy/${id}-tokens`, {rules: tokenPolicy}, wvt);
            const envPolicyResp = await api.put(`/sys/policy/${id}-environments`, {rules: '#'}, wvt);
            const claccPolicyResp = await api.put(`/sys/policy/${id}-cloud-accounts`, {rules: '#'}, wvt);
            if (goodStatus(tokenPolicyResp, envPolicyResp, claccPolicyResp)) {
                const rolePath = `/auth/approle/role/${id}`;
                const role = {
                    period: 3600,
                    bind_secret_id: true,
                    policies: [`${id}-tokens`, `${id}-environments`, `${id}-cloud-accounts`]
                };
                const roleResp = await api.post(rolePath, role, wvt);
                if (goodStatus(roleResp)) {
                    const roleIdResp = await api.get(`${rolePath}/role-id`, wvt);
                    if (roleIdResp.status === 200) {
                        const roleId = roleIdResp.data.data.role_id;
                        ctx.status = 201;
                        ctx.body = {roleId};
                    } else {
                        logger.warn('Unexpected status %d from Vault fetching role `%s` role-id: %j',
                            roleIdResp.status, id, roleIdResp.data);
                        ctx.status = proxyErrorStatus(roleIdResp);
                    }
                } else {
                    logger.warn('Unexpected status %d from Vault while creating role `%s`: %j',
                        roleResp.status, id, roleResp.data);
                    ctx.status = proxyErrorStatus(roleResp);
                }
            } else {
                printBadResponses(logger.warn, 'Unexpected status %d from Vault while creating policies for `%s`: %j',
                    id, tokenPolicyResp, envPolicyResp, claccPolicyResp);
                ctx.status = proxyErrorStatus(tokenPolicyResp, envPolicyResp, claccPolicyResp);
            }
        }
    },

    async delete(ctx) {
        const id = ctx.params.id;
        if (id.startsWith('stub-')) {
            const deleted = stubUsers.delete(id);
            if (deleted) {
                ctx.status = 204;
            } else {
                throw new NotFoundError();
            }
        } else {
            const wvt = withToken(ctx.vaultToken);
            const rolePath = `/auth/approle/role/${id}`;
            const roleIdResp = await api.get(`${rolePath}/role-id`, wvt);
            if (roleIdResp.status === 200) {
                let error = false;

                const roleDeleteResp = await api.delete(rolePath, wvt);
                if (roleDeleteResp.status !== 204) {
                    logger.warn('Unexpected status %d from Vault while deleting role `%s`: %j',
                        roleDeleteResp.status, id, roleDeleteResp.data);
                    error = true;
                }

                const policyDeleteResp = await api.delete(`/sys/policy/${id}`, wvt);
                if (policyDeleteResp.status !== 204) {
                    logger.warn('Unexpected status %d from Vault while deleting policy `%s`: %j',
                        policyDeleteResp.status, id, policyDeleteResp.data);
                    error = true;
                }

                if (!error) {
                    ctx.status = 204;
                } else {
                    // TODO: handle this type of errors in common way
                    ctx.status = proxyErrorStatus(roleDeleteResp);
                }
            } else {
                ctx.status = roleIdResp.status;
            }
        }
    },

    environments(ctx) {
        return updatePolicy(ctx, 'environments', environmentPolicyFragment);
    },

    cloudAccounts(ctx) {
        return updatePolicy(ctx, 'cloud-accounts', cloudAccountPolicyFragment);
    },

    async login(ctx) {
        const id = ctx.params.id;
        const roleId = ctx.request.body.roleId;
        if (roleId) {
            if (id.startsWith('stub-')) {
                const user = stubUsers.get(id);
                if (user.roleId === roleId) {
                    ctx.status = 200;
                    ctx.body = {
                        token: 'c9086cfc-c1a4-4609-546d-1f9d860c8ac3',
                        ttl: 3600
                    };
                } else {
                    throw new BadRequestError('`roleId` does not match');
                }
            } else {
                const wvt = withToken(ctx.vaultToken);
                const respSecretId = await api.post(`/auth/approle/role/${id}/secret-id`, undefined, wvt);
                if (goodStatus(respSecretId)) {
                    const secretId = respSecretId.data.data.secret_id;
                    const respLogin = await api.post('/auth/approle/login',
                        {role_id: roleId, secret_id: secretId}, wvt);
                    if (respLogin.status === 200) {
                        ctx.status = 200;
                        ctx.body = {
                            token: respLogin.data.auth.client_token,
                            ttl: respLogin.data.auth.lease_duration
                        };
                    } else {
                        // TODO: handle this type of errors in common way
                        logger.warn('Unexpected status %d from Vault during role `%s` login: %j',
                            respLogin.status, id, respLogin.data);
                        ctx.status = proxyErrorStatus(respLogin);
                    }
                } else {
                    // TODO: handle this type of errors in common way
                    logger.warn('Unexpected status %d from Vault while obtaining secret for role `%s`: %j',
                        respSecretId.status, id, respSecretId.data);
                    ctx.status = proxyErrorStatus(respSecretId);
                }
            }
        } else {
            throw new BadRequestError('`roleId` field is not set');
        }
    }
};
