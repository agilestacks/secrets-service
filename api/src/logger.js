const winston = require('winston');

function loggerFactory(additionalMeta) {
    const rewriters = additionalMeta
        ? [(level, msg, meta) => ({...meta, ...additionalMeta})]
        : undefined;

    return new winston.Logger({
        transports: [
            new winston.transports.Console({
                handleExceptions: true,
                humanReadableUnhandledException: true,
                timestamp: true,
                colorize: true,
                prettyPrint: true,
                json: false
            })
        ],
        exitOnError: false,
        level: 'debug',
        rewriters
    });
}

module.exports.logger = loggerFactory();
module.exports.loggerFactory = loggerFactory;
