const {camelCase} = require('lodash');
const {api, withToken, goodStatus, proxyErrorStatus, printBadResponses} = require('../vault');
const {logger} = require('../logger');
const {NotFoundError, BadRequestError} = require('../errors');
const {allowedEntities, checkEntityKind} = require('../validate');

const stubUsers = new Map(); // Jest tests

const policyTemplate = `
path "secret/{{entityKind}}/{{entityId}}/*" {
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

module.exports = {
    async create(ctx) {
        const {params: {id}} = ctx;
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

            const tokenPolicyResp = await api.put(`/sys/policy/${id}-tokens`, {
                policy: tokenPolicy
            }, wvt);

            const policies = allowedEntities.map(entity => `${id}-${entity}`);

            const policiesResp = await Promise.all(policies
                .map(policy => api.put(`/sys/policy/${policy}`, {policy: '#'}, wvt))
            );

            if (goodStatus(tokenPolicyResp, ...policiesResp)) {
                const rolePath = `/auth/approle/role/${id}`;
                const rolePoliciesResp = await api.post(`${rolePath}/policies`, {policies}, wvt);
                const requestRole = !goodStatus(rolePoliciesResp); // 404
                let roleResp;
                if (requestRole) {
                    const role = {
                        period: 7200,
                        bind_secret_id: true,
                        secret_id_ttl: 60,
                        secret_id_num_uses: 1,
                        policies
                    };
                    roleResp = await api.post(rolePath, role, wvt);
                }
                if (!requestRole || goodStatus(roleResp)) {
                    const roleIdResp = await api.get(`${rolePath}/role-id`, wvt);
                    if (roleIdResp.status === 200) {
                        const roleId = roleIdResp.data.data.role_id;
                        ctx.status = requestRole ? 201 : 200;
                        ctx.body = {roleId};
                    } else {
                        logger.warn(
                            'Unexpected status %d from Vault fetching role `%s` role-id: %j',
                            roleIdResp.status, id, roleIdResp.data
                        );
                        ctx.status = proxyErrorStatus(roleIdResp);
                    }
                } else {
                    logger.warn(
                        'Unexpected status %d from Vault while creating role `%s`: %j',
                        roleResp.status, id, roleResp.data
                    );
                    ctx.status = proxyErrorStatus(roleResp);
                }
            } else {
                printBadResponses(
                    logger.warn,
                    'Unexpected status %d from Vault while creating policies for `%s`: %j',
                    id, tokenPolicyResp, ...policiesResp
                );
                ctx.status = proxyErrorStatus(tokenPolicyResp, ...policiesResp);
            }
        }
    },

    async delete(ctx) {
        const {params: {id}} = ctx;
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
                const roleDeleteResp = await api.delete(rolePath, wvt);
                if (roleDeleteResp.status === 204) {
                    const tokenPolicyDelResp = await api.delete(`/sys/policy/${id}-tokens`, wvt);

                    const policies = allowedEntities.map(entity => `${id}-${entity}`);

                    const policiesResp = await Promise.all(policies
                        .map(policy => api.delete(`/sys/policy/${policy}`, wvt))
                    );
                    // allow missing policies
                    if (goodStatus(tokenPolicyDelResp, ...policiesResp.filter(response => !response.status === 404))) {
                        ctx.status = 204;
                    } else {
                        printBadResponses(
                            logger.warn,
                            'Unexpected status %d from Vault while deleting policies for `%s`: %j',
                            id, tokenPolicyDelResp, ...policiesResp
                        );
                        // TODO: handle this type of errors in common way
                        ctx.status = proxyErrorStatus(tokenPolicyDelResp, ...policiesResp);
                    }
                } else {
                    logger.warn('Unexpected status %d from Vault while deleting role `%s`: %j',
                        roleDeleteResp.status, id, roleDeleteResp.data);
                    ctx.status = roleDeleteResp.status;
                }
            } else {
                ctx.status = roleIdResp.status;
            }
        }
    },

    async update(ctx) {
        const {
            params: {id, entityKind},
            request: {body}
        } = ctx;
        checkEntityKind(entityKind);
        const entityCamelCase = camelCase(entityKind);
        const list = body[entityCamelCase];
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
                const policyPath = `/sys/policy/${id}-${entityKind}`;
                const policyResp = await api.get(policyPath, wvt);
                if (policyResp.status === 200) {
                    const policyRules = list
                        .map(entityId => policyTemplate
                            .replace('{{entityKind}}', entityKind)
                            .replace('{{entityId}}', entityId))
                        .join('\n');
                    const resp = await api.put(policyPath, {rules: policyRules || '#'}, wvt);
                    if (goodStatus(resp)) {
                        ctx.status = 204;
                    } else {
                        logger.warn(
                            'Unexpected status %d from Vault while updating policy `%s-%s`: %j',
                            policyResp.status, id, entityKind, resp.data
                        );
                        ctx.status = proxyErrorStatus(resp);
                    }
                } else {
                    ctx.status = policyResp.status;
                }
            }
        } else {
            throw new BadRequestError(`'${entityCamelCase}' field is not set`);
        }
    },

    async login(ctx) {
        const {params: {id}, request: {body: {roleId}}} = ctx;
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
                        logger.warn('Unexpected status %d from Vault during role `%s` login: %j',
                            respLogin.status, id, respLogin.data);
                        ctx.status = proxyErrorStatus(respLogin);
                    }
                } else {
                    logger.warn('Unexpected status %d from Vault while obtaining secret-id for role `%s`: %j',
                        respSecretId.status, id, respSecretId.data);
                    ctx.status = proxyErrorStatus(respSecretId);
                }
            }
        } else {
            throw new BadRequestError('`roleId` field is not set');
        }
    }
};
