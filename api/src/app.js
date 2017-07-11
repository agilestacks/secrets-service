const apiPrefix = '/api/v1';

const Koa = require('koa');
const parser = require('koa-bodyparser');
const Router = require('koa-router');
const {loggerFactory} = require('./logger');
const {ApiError, ErrorWrapper, ForbiddenError} = require('./errors');

const version = require('./controllers/version');

const app = new Koa();

const routerConf = {
    prefix: apiPrefix
};
const router = new Router(routerConf);
const publicRouter = new Router(routerConf);

publicRouter.get('/ping', (ctx) => {
    ctx.body = 'pong';
});
router.get('/version', version.get);

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

        logger.info('HTTP Request', {method, url});
        logger.debug('HTTP Request body: %j', request.body);
        try {
            await next();
        } catch (e) {
            logger.warn('Error', e);
        }

        logger.debug('HTTP Response: %j', ctx.body, {status: ctx.status});
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
            ctx.user = {token};
            await next();
        } else {
            throw new ForbiddenError();
        }
    })
    .use(router.routes())
    .use(router.allowedMethods());
