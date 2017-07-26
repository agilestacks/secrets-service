const users = new Map();

module.exports = {
    create(ctx) {
        const roleId = 'f2db06c7-1b3c-9262-1116-fa1842a5c567';
        const id = ctx.params.id;
        const user = {id, roleId};
        users.set(id, user);
        ctx.status = 201;
        ctx.body = {roleId};
    },

    delete(ctx) {
        const id = ctx.params.id;
        ctx.status = users.delete(id) ? 204 : 404;
    },

    environments(ctx) {
        const id = ctx.params.id;
        const environments = ctx.request.body.environments;
        if (environments) {
            ctx.status = users.get(id) ? 204 : 404;
        } else {
            ctx.status = 400;
            ctx.body = {error: '`environments` field is not set'};
        }
    },

    login(ctx) {
        const id = ctx.params.id;
        const roleId = ctx.request.body.roleId;
        if (roleId) {
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
            ctx.status = 400;
            ctx.body = {error: '`roleId` field is not set'};
        }
    }
};
