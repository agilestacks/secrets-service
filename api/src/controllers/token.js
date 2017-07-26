module.exports = {
    renew(ctx) {
        ctx.body = {ttl: 3600};
    },

    revoke(ctx) {
        ctx.status = 204;
    }
};
