const {logger} = require('./src/logger');
const app = require('./src/app');

const port = process.env.SECRETS_PORT || 3002;

app.listen(port, () => {
    logger.info('Listening %s', port);
});
