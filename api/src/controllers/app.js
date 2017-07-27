const {api} = require('../vault');

const knownApps = ['authentication-service', 'automation-hub'];

async function loginRole(roleId) {
    const respLogin = await api.post('/auth/approle/login', {role_id: roleId});
    return {
        token: respLogin.data.auth.client_token,
        ttl: respLogin.data.auth.lease_duration
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
            const {token: highPrivToken, ttl: ttlH} = await loginRole(roleIdHigh);
            const {token: lowPrivToken, ttl: ttlL} = await loginRole(roleIdLow);
            const ttl = Math.min(ttlH, ttlL);
            ctx.status = 200;
            ctx.body = {highPrivToken, lowPrivToken, ttl};
        }
    }
};
