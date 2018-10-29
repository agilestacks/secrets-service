const {createLogger, format, transports} = require('winston');
const {MESSAGE} = require('triple-beam');
const {inspect} = require('util');

const {combine, timestamp, splat, colorize} = format;

const idGenerator = {
    id: new Date().getTime(),
    next() {
        this.id = (this.id % (Number.MAX_SAFE_INTEGER - 1)) + 1;
        return this.id.toString(36);
    }
};

const outputFormat = format((info, loggerId) => {
    const meta = inspect((info.meta || {}), {
        colors: true,
        compact: false,
        breakLength: 100
    });

    let message = `${info.timestamp} - ${loggerId} - ${info.level}: ${info.message}`;

    if (meta !== '{}') {
        message = `${message}\n${meta}`;
    }

    return {
        ...info,
        [MESSAGE]: message
    };
});

function loggerFactory() {
    const loggerId = idGenerator.next();

    return createLogger({
        level: 'debug',
        format: combine(
            timestamp(),
            colorize({level: true}),
            splat(),
            outputFormat(loggerId)
        ),
        transports: [
            new transports.Console({
                handleExceptions: true
            })
        ],
        exitOnError: false
    });
}

module.exports.logger = loggerFactory();
module.exports.loggerFactory = loggerFactory;
