module.exports = {
    login(ctx) {
        const roleIdHigh = ctx.request.body.highPrivRoleId;
        const roleIdLow = ctx.request.body.lowPrivRoleId;
        if (roleIdHigh && roleIdLow) {
            ctx.status = 200;
            ctx.body = {
                highPrivToken: '89b144e3-d785-46b4-ac3f-5cc504bfc624',
                lowPrivToken: '4f5b5510-a6ac-41e1-b4bc-bcff4f522769',
                ttl: 3600
            };
        } else {
            ctx.status = 400;
            ctx.body = {error: 'Either `highPrivRoleId` or `lowPrivRoleId` field is not set'};
        }
    }
};
