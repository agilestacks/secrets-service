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

secretC.setApiPrefix(apiPrefix);

const app = new Koa();

const routerConf = {
    prefix: apiPrefix
};
const router = new Router(routerConf);
const publicRouter = new Router(routerConf);

publicRouter.get('/ping', (ctx) => {
    ctx.body = 'pong';
});
publicRouter.get('/version', versionC.get);

router.put('/users/:id', userC.create);
router.del('/users/:id', userC.delete);
router.put('/users/:id/environments', userC.environments);
router.post('/users/:id/login', userC.login);

publicRouter.post('/apps/:id/login', appC.login);

router.post('/environments/:environmentId/secrets', secretC.create);
router.put('/environments/:environmentId/secrets/:id', secretC.update);
router.get('/environments/:environmentId/secrets/:id', secretC.get);
router.del('/environments/:environmentId/secrets/:id', secretC.delete);
router.post('/environments/:environmentId/secrets/:id/session-keys', secretC.sessionKeys);

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
        const {method, url, request} = ctx;

        const logger = loggerFactory({requestId: idGenerator.next()});
        ctx.logger = logger;

        logger.debug('HTTP <<<: %s %s', method, url);
        logger.silly('HTTP <<<: X-Secrets-Token: %s', request.headers['x-secrets-token']);
        logger.silly('HTTP <<<: %j', request.body);
        try {
            await next();
        } catch (e) {
            logger.warn('Error', e);
        }

        logger.debug('HTTP ===: %d', ctx.status);
        logger.silly('HTTP ===: %j', ctx.body);
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
