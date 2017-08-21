const {api, withToken, goodStatus, proxyErrorStatus} = require('../vault');
const {logger} = require('../logger');

module.exports = {
    async renew(ctx) {
        const resp = await api.post('/auth/token/renew-self', undefined, withToken(ctx.vaultToken));
        if (goodStatus(resp)) {
            if (ctx.vaultToken !== resp.data.auth.client_token) {
                logger.error('Vault sent different token during renew via /auth/token/renew-self');
            }
            ctx.status = 200;
            ctx.body = {ttl: resp.data.auth.lease_duration};
        } else {
            // TODO: handle this type of errors in common way
            logger.warn('Unexpected status %d from Vault during token renewal: %j',
                resp.status, resp.data);
            ctx.status = proxyErrorStatus(resp);
        }
    },

    async revoke(ctx) {
        const resp = await api.post('/auth/token/revoke-self', undefined, withToken(ctx.vaultToken));
        if (goodStatus(resp)) {
            ctx.status = 204;
        } else {
            // TODO: handle this type of errors in common way
            logger.warn('Unexpected status %d from Vault during token revocation: %j',
                resp.status, resp.data);
            ctx.status = proxyErrorStatus(resp);
        }
    }
};
