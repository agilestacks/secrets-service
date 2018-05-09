const apiPrefix = '/api/v1';

const Koa = require('koa');
const parser = require('koa-bodyparser');
const Router = require('koa-router');
const {loggerFactory} = require('./logger');
const {ApiError, ErrorWrapper, ForbiddenError} = require('./errors');

const versionC = require('./controllers/version');
const userC = require('./controllers/user');
const secretC = require('./controllers/secret');
const appC = require('./controllers/app');
const tokenC = require('./controllers/token');

const app = new Koa();

const routerConf = {
    prefix: apiPrefix
};
const router = new Router(routerConf);
const publicRouter = new Router(routerConf);
const pingRouter = new Router(routerConf);

pingRouter.use(async (ctx, next) => {
    const {method, url, logger} = ctx;
    logger.silly('PING Request <<< %s %s', method, url);

    try {
        await next();
    } catch (error) {
        logger.error('Error', {error});
    }

    logger.silly('PING Response >>> %d', ctx.status);
});
pingRouter.get('/ping', (ctx) => {
    ctx.body = 'pong';
});

publicRouter.get('/ping', (ctx) => {
    ctx.body = 'pong';
});
publicRouter.get('/version', versionC.get);

publicRouter.post('/apps/:id/login', appC.login);

router.put('/users/:id', userC.create);
router.del('/users/:id', userC.delete);
router.put('/users/:id/:entityKind', userC.update);
router.post('/users/:id/login', userC.login);

router.post('/secrets/:entityKind/:entityId', secretC.create);
router.post('/secrets/:entityKind/:entityId/copy/:fromEntityKind/:fromEntityId/:fromId', secretC.createFrom);
router.put('/secrets/:entityKind/:entityId/:id', secretC.update);
router.get('/secrets/:entityKind/:entityId/:id', secretC.get);
router.del('/secrets/:entityKind/:entityId/:id', secretC.delete);
router.del('/secrets/:entityKind/:entityId', secretC.deleteAll);
router.post('/secrets/:entityKind/:entityId/:id/session-keys', secretC.sessionKeys);

router.post('/tokens/renew', tokenC.renew);
router.post('/tokens/revoke', tokenC.revoke);

const idGenerator = {
    id: new Date().getTime(),
    next() {
        this.id = (this.id % (Number.MAX_SAFE_INTEGER - 1)) + 1;
        return this.id.toString(36);
    }
};

module.exports = app
    .use(parser())
    .use(async (ctx, next) => {
        ctx.logger = loggerFactory({requestId: idGenerator.next()});
        await next();
    })
    .use(pingRouter.routes())
    .use(pingRouter.allowedMethods())
    .use(async (ctx, next) => {
        const {method, url, request, logger} = ctx;

        logger.debug('HTTP <<< %s %s', method, url);
        logger.silly('HTTP <<< X-Secrets-Token: %s', request.headers['x-secrets-token']);
        logger.silly('HTTP <<< %j', request.body);
        try {
            await next();
        } catch (e) {
            logger.warn('Error', e);
        }

        logger.debug('HTTP === %d', ctx.status);
        logger.silly('HTTP === %j', ctx.body);
    })
    .use(async (ctx, next) => {
        try {
            await next();
        } catch (err) {
            const wrappedError = (err instanceof ApiError)
                ? err
                : new ErrorWrapper(err);

            ctx.status = wrappedError.status || 500;
            ctx.body = {errors: wrappedError.toResponse()};

            ctx.app.emit('error', wrappedError, ctx);
        }
    })
    .use(publicRouter.routes())
    .use(publicRouter.allowedMethods())
    .use(async (ctx, next) => {
        const {request: {headers: {
            'x-secrets-token': token
        }}} = ctx;

        if (token) {
            ctx.vaultToken = token;
            await next();
        } else {
            throw new ForbiddenError();
        }
    })
    .use(router.routes())
    .use(router.allowedMethods());
