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
            type: 'serverError',
            source: this.source,
            detail: this.message,
            meta: Object.assign({}, this.meta, {stack: this.stack})
        }];
    }
}

class ValidationError extends ApiError {
    constructor(errors) {
        super('validation error');

        this.status = 400;
        this.errors = errors;
    }

    toResponse() {
        return this.errors.map(err => ({
            type: 'badRequest',
            source: err.dataPath,
            detail: err.message,
            meta: err
        }));
    }
}

const errorTypes = {
    400: 'badRequest',
    403: 'forbidden',
    404: 'notFound',
    500: 'serverError'
};

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
            meta: Object.assign({}, this.meta, {
                stack: this.stack
            })
        }];
    }
}

class ForbiddenError extends ApiError {
    constructor(message = 'Operation is not permitted to current user') {
        super(message);

        this.status = 403;
    }

    toResponse() {
        return [{
            type: 'forbidden',
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
            type: 'notFound',
            detail: this.message,
            meta: Object.assign({}, this.meta, {stack: this.stack})
        }];
    }
}

exports.ApiError = ApiError;
exports.ServerError = ServerError;
exports.ValidationError = ValidationError;
exports.ErrorWrapper = ErrorWrapper;
exports.ForbiddenError = ForbiddenError;
exports.NotFoundError = NotFoundError;
