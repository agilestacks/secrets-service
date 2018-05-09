const errorTypes = {
    400: 'badRequest',
    403: 'forbidden',
    404: 'notFound',
    500: 'serverError'
};

class ApiError extends Error {}

class ServerError extends ApiError {
    constructor(message, {source, status, meta} = {}) {
        super(message);

        // Capture stack trace, excluding constructor call from it.
        Error.captureStackTrace(this, this.constructor);

        this.status = status || 500;
        this.meta = meta || {};
        this.source = source || null;
    }

    toResponse() {
        return [{
            type: errorTypes[this.status] || errorTypes[500],
            source: this.source,
            detail: this.message,
            meta: {...this.meta, ...{stack: this.stack}}
        }];
    }
}

class BadRequestError extends ApiError {
    constructor(message = 'Bad Request', status = 400, meta = {}) {
        super(message);

        this.status = status;
        this.meta = meta;
    }

    toResponse() {
        return {
            type: errorTypes[this.status] || errorTypes[400],
            detail: this.message,
            meta: {...this.meta, ...{stack: this.stack}}
        };
    }
}

class ErrorWrapper extends ApiError {
    constructor(error, meta = {}) {
        super(error.message);

        this.stack = error.stack || this.stack;
        this.status = error.status || 500;
        this.error = error;
        this.meta = meta;
    }

    toResponse() {
        return [{
            type: errorTypes[this.status] || errorTypes[500],
            detail: this.error.message,
            meta: {...this.meta, ...{stack: this.stack}}
        }];
    }
}

class ForbiddenError extends ApiError {
    constructor(message = 'Operation is not permitted') {
        super(message);

        this.status = 403;
    }

    toResponse() {
        return [{
            type: errorTypes[this.status],
            detail: this.message
        }];
    }
}


class NotFoundError extends ApiError {
    constructor(message = 'Entity not found', meta = {}) {
        super(message);

        // Capture stack trace, excluding constructor call from it.
        Error.captureStackTrace(this, this.constructor);

        this.status = 404;
        this.meta = meta;
    }

    toResponse() {
        return [{
            type: errorTypes[this.status],
            detail: this.message,
            meta: {...this.meta, ...{stack: this.stack}}
        }];
    }
}

exports.ApiError = ApiError;
exports.ServerError = ServerError;
exports.BadRequestError = BadRequestError;
exports.ErrorWrapper = ErrorWrapper;
exports.ForbiddenError = ForbiddenError;
exports.NotFoundError = NotFoundError;
