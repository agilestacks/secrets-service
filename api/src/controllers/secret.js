const uuidv4 = require('uuid/v4');

const secrets = new Map();

let apiPrefix = '';

module.exports = {
    setApiPrefix(prefix) {
        apiPrefix = prefix;
    },

    create(ctx) {
        const envId = ctx.params.environmentId;
        const id = uuidv4();
        const secret = Object.assign({}, ctx.request.body, {id});
        secrets.set(id, secret);
        ctx.status = 201;
        ctx.set('Location', `${apiPrefix}/environments/${envId}/secrets/${id}`);
        ctx.body = {id};
    },

    update(ctx) {
        const id = ctx.params.id;
        const update = ctx.request.body;
        const secret = secrets.get(id);
        if (secret) {
            if (secret.kind === update.kind) {
                const newSecret = Object.assign({}, update, {id});
                secrets.set(id, newSecret);
                ctx.status = 204;
            } else {
                ctx.status = 409;
            }
        } else {
            ctx.status = 404;
        }
    },

    delete(ctx) {
        const id = ctx.params.id;
        ctx.status = secrets.delete(id) ? 204 : 404;
    },

    get(ctx) {
        const id = ctx.params.id;
        const secret = secrets.get(id);
        if (secret) {
            ctx.status = 200;
            ctx.body = secret;
        } else {
            ctx.status = 404;
        }
    },

    sessionKeys(ctx) {
        const id = ctx.params.id;
        const secret = secrets.get(id);
        if (secret) {
            ctx.status = 200;
            ctx.body = {
                cloud: 'aws',
                accessKey: 'AKIA****************',
                secretKey: 'IqCFm0**********************************',
                sessionToken: '...'
            };
        } else {
            ctx.status = 404;
        }
    }
};
