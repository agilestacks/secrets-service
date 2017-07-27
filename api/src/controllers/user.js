const {api, withToken} = require('../vault');
const {logger} = require('../logger');

const users = new Map(); // to save test stubs

const environmentPolicyFragment = `
path "secret/environments/{{env}}/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
`;

const tokenPolicyFragment = `
path "auth/token/renew-self" {
  capabilities = ["update"]
}

path "auth/token/revoke-self" {
  capabilities = ["update"]
}
`;

const goodStatus = status => [200, 201, 204].some(good => good === status);

module.exports = {
    async create(ctx) {
        const id = ctx.params.id;
        if (id.startsWith('stub-')) {
            const roleId = 'f2db06c7-1b3c-9262-1116-fa1842a5c567';
            const user = {id, roleId};
            users.set(id, user);
            ctx.status = 201;
            ctx.body = {roleId};
        } else if (!id.startsWith('okta-')) {
            ctx.status = 400;
            ctx.body = {error: `User id must start with okta-, got ${id}`};
        } else {
            const rules = tokenPolicyFragment;
            const policyResp = await api.put(`/sys/policy/${id}`, {rules}, withToken(ctx.vaultToken));
            if (goodStatus(policyResp.status)) {
                const rolePath = `/auth/approle/role/${id}`;
                const role = {
                    period: 3600,
                    bind_secret_id: true,
                    policies: id
                };
                const roleResp = await api.post(rolePath, role, withToken(ctx.vaultToken));
                if (goodStatus(roleResp.status)) {
                    const roleIdResp = await api.get(`${rolePath}/role-id`, withToken(ctx.vaultToken));
                    if (roleIdResp.status === 200) {
                        const roleId = roleIdResp.data.data.role_id;
                        ctx.status = 201;
                        ctx.body = {roleId};
                    } else {
                        logger.warn('Unexpected status %d from Vault fetching role `%s` role-id: %j',
                            roleIdResp.status, id, roleIdResp.data);
                        ctx.status = roleIdResp.status === 403 ? 403 : 502;
                    }
                } else {
                    logger.warn('Unexpected status %d from Vault while creating role `%s`: %j',
                        roleResp.status, id, roleResp.data);
                    ctx.status = roleResp.status === 403 ? 403 : 502;
                }
            } else {
                logger.warn('Unexpected status %d from Vault while creating policy `%s`: %j',
                    policyResp.status, id, policyResp.data);
                ctx.status = policyResp.status === 403 ? 403 : 502;
            }
        }
    },

    async delete(ctx) {
        const id = ctx.params.id;
        if (id.startsWith('stub-')) {
            ctx.status = users.delete(id) ? 204 : 404;
        } else {
            const rolePath = `/auth/approle/role/${id}`;
            const roleIdResp = await api.get(`${rolePath}/role-id`, withToken(ctx.vaultToken));
            if (roleIdResp.status === 200) {
                let error = false;

                const roleDeleteResp = await api.delete(rolePath, withToken(ctx.vaultToken));
                if (roleDeleteResp.status !== 204) {
                    logger.warn('Unexpected status %d from Vault while deleting role `%s`: %j',
                        roleDeleteResp.status, id, roleDeleteResp.data);
                    error = true;
                }

                const policyDeleteResp = await api.delete(`/sys/policy/${id}`, withToken(ctx.vaultToken));
                if (policyDeleteResp.status !== 204) {
                    logger.warn('Unexpected status %d from Vault while deleting policy `%s`: %j',
                        policyDeleteResp.status, id, policyDeleteResp.data);
                    error = true;
                }

                if (!error) {
                    ctx.status = 204;
                } else {
                    ctx.status = roleDeleteResp.status === 403 || policyDeleteResp.status === 403 ? 403 : 502;
                }
            } else {
                ctx.status = roleIdResp.status;
            }
        }
    },

    async environments(ctx) {
        const id = ctx.params.id;
        const environments = ctx.request.body.environments;
        if (environments) {
            if (id.startsWith('stub-')) {
                ctx.status = users.get(id) ? 204 : 404;
            } else {
                const policyPath = `/sys/policy/${id}`;
                const policyResp = await api.get(policyPath, withToken(ctx.vaultToken));
                if (policyResp.status === 200) {
                    const environmentsPolicy = environments.map(env =>
                        environmentPolicyFragment.replace('{{env}}', env)).join('\n');
                    const rules = [environmentsPolicy, tokenPolicyFragment].join('\n');
                    const policyPutResp = await api.put(policyPath, {rules}, withToken(ctx.vaultToken));
                    if (goodStatus(policyPutResp.status)) {
                        ctx.status = 204;
                    } else {
                        logger.warn('Unexpected status %d from Vault while updating policy `%s`: %j',
                            policyResp.status, id, policyPutResp.data);
                        ctx.status = policyPutResp.status === 403 ? 403 : 502;
                    }
                } else {
                    ctx.status = policyResp.status;
                }
            }
        } else {
            ctx.status = 400;
            ctx.body = {error: '`environments` field is not set'};
        }
    },

    async login(ctx) {
        const id = ctx.params.id;
        const roleId = ctx.request.body.roleId;
        if (roleId) {
            if (id.startsWith('stub-')) {
                const user = users.get(id);
                if (user.roleId === roleId) {
                    ctx.status = 200;
                    ctx.body = {
                        token: 'c9086cfc-c1a4-4609-546d-1f9d860c8ac3',
                        ttl: 3600
                    };
                } else {
                    ctx.status = 400;
                    ctx.body = {error: '`roleId` does not match'};
                }
            } else {
                const respSecretId = await api.post(`/auth/approle/role/${id}/secret-id`, undefined,
                    withToken(ctx.vaultToken));
                if (goodStatus(respSecretId.status)) {
                    const secretId = respSecretId.data.data.secret_id;
                    const respLogin = await api.post('/auth/approle/login', {role_id: roleId, secret_id: secretId},
                        withToken(ctx.vaultToken));
                    if (respLogin.status === 200) {
                        ctx.status = 200;
                        ctx.body = {
                            token: respLogin.data.auth.client_token,
                            ttl: respLogin.data.auth.lease_duration
                        };
                    } else {
                        logger.warn('Unexpected status %d from Vault while login-in role `%s`: %j',
                            respLogin.status, id, respLogin.data);
                        ctx.status = respLogin.status === 403 ? 403 : 502;
                    }
                } else {
                    logger.warn('Unexpected status %d from Vault while obtaining secret for role `%s`: %j',
                        respSecretId.status, id, respSecretId.data);
                    ctx.status = respSecretId.status === 403 ? 403 : 502;
                }
            }
        } else {
            ctx.status = 400;
            ctx.body = {error: '`roleId` field is not set'};
        }
    }
};
