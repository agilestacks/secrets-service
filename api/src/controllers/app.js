const {api, goodStatus, proxyErrorStatus} = require('../vault');
const {logger} = require('../logger');

const knownApps = ['authentication-service', 'automation-hub'];

async function loginRole(roleId) {
    const respLogin = await api.post('/auth/approle/login', {role_id: roleId});
    if (goodStatus(respLogin)) {
        return {
            token: respLogin.data.auth.client_token,
            ttl: respLogin.data.auth.lease_duration
        };
    }
    logger.warn('Unexpected status %d from Vault during role `%s` login: %j',
        respLogin.status, roleId, respLogin.data);
    return {
        error: proxyErrorStatus(respLogin)
    };
}

module.exports = {
    async login(ctx) {
        const app = ctx.params.id;
        const known = knownApps.some(name => name === app);
        const roleIdHigh = ctx.request.body.highPrivRoleId;
        const roleIdLow = ctx.request.body.lowPrivRoleId;
        if (!known) {
            ctx.status = 400;
            ctx.body = {error: `\`${app}\` is not known application`};
        } else if (!roleIdHigh || !roleIdLow) {
            ctx.status = 400;
            ctx.body = {error: 'Either `highPrivRoleId` or `lowPrivRoleId` field is not set'};
        } else {
            const {token: highPrivToken, ttl: ttlH, error: errorH} = await loginRole(roleIdHigh);
            const {token: lowPrivToken, ttl: ttlL, error: errorL} = await loginRole(roleIdLow);
            const ttl = Math.min(ttlH, ttlL);
            if (errorH || errorL) {
                ctx.status = errorH || errorL;
            } else {
                ctx.status = 200;
                ctx.body = {highPrivToken, lowPrivToken, ttl};
            }
        }
    }
};
