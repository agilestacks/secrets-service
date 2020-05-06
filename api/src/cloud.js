const crypto = require('crypto');
const {pick: lopick} = require('lodash');
const aws = require('aws-sdk');
const awsConfig = require('aws-config');
const {cloudAllowedFields} = require('./validate');
const {maskRole, maskKey} = require('./mask');
const {BadRequestError, ServerError} = require('./errors');

aws.config = awsConfig();
const stsTtl = 3600;

const randomSuf = () => crypto.randomBytes(3).toString('hex');

function awsAssumeRole(roleName, externalId, {duration, purpose, credentials, ...options}) {
    const sts = new aws.STS({...awsConfig(options), credentials});
    const prefix = purpose.substring(0, 57).replace(/[^\w+=,.@-]/g, '-');
    const params = {
        RoleArn: roleName,
        ExternalId: externalId,
        RoleSessionName: `${prefix}-${randomSuf()}`, // max length is 64
        DurationSeconds: duration
    };
    return sts.assumeRole(params).promise();
}

function awsGetSessionToken(accessKeyId, secretAccessKey, {duration, ...options}) {
    const sts = new aws.STS(awsConfig({accessKeyId, secretAccessKey, ...options}));
    const params = {
        DurationSeconds: duration
    };
    return sts.getSessionToken(params).promise();
}

async function awsSession(secret, requestBody, credentials = null) {
    let {duration, sts, region} = requestBody || {};
    const secretDuration = parseInt(secret.duration, 10);
    if (!duration) {
        duration = secretDuration || stsTtl;
    }
    if (secretDuration && duration > secretDuration) {
        duration = secretDuration;
    }
    duration = parseInt(duration, 10);
    // The requested DurationSeconds exceeds the 1 hour session limit for roles assumed by role chaining
    if (credentials && credentials.sessionToken && duration > 3600) {
        duration = 3600;
    }
    if (!sts) sts = secret.sts; // eslint-disable-line prefer-destructuring
    if (!region) region = secret.region; // eslint-disable-line prefer-destructuring

    let stsReply;
    if (secret.roleArn) {
        const purpose = (requestBody && requestBody.purpose)
            ? requestBody.purpose
            : 'automation';
        try {
            stsReply = await awsAssumeRole(secret.roleArn, secret.externalId,
                {purpose, duration, region, endpoint: sts, credentials});
        } catch (err) {
            throw new ServerError(
                `AWS STS error assuming role '${maskRole(secret.roleArn)}': ${err}`,
                {status: 502}
            );
        }
    } else if (secret.accessKey && secret.secretKey) {
        try {
            stsReply = await awsGetSessionToken(secret.accessKey, secret.secretKey,
                {duration, region, endpoint: sts});
        } catch (err) {
            throw new ServerError(
                `AWS STS error getting session token for '${maskKey(secret.accessKey)}': ${err}`,
                {status: 502}
            );
        }
    } else {
        throw new BadRequestError(
            'The requested secret has no `roleArn`, nor `accessKey` with `secretKey` defined',
            405
        );
    }

    const creds = stsReply.Credentials;
    return {
        accessKey: creds.AccessKeyId,
        secretKey: creds.SecretAccessKey,
        sessionToken: creds.SessionToken,
        ttl: duration,
        ...(region ? {region} : {}),
        ...(sts ? {sts} : {}),
        _env: {
            AWS_ACCESS_KEY_ID: creds.AccessKeyId,
            AWS_SECRET_ACCESS_KEY: creds.SecretAccessKey,
            AWS_SESSION_TOKEN: creds.SessionToken,
            ...(region ? {AWS_DEFAULT_REGION: region} : {})
        }
    };
}

async function awsSessionVia(secret, viaSecret, requestBody) {
    // only Role session is allowed Via
    if (!secret.roleArn) {
        throw new BadRequestError('The requested secret has no `roleArn` defined', 405);
    }
    const via = viaSecret.roleArn ?
        await awsSession(viaSecret, requestBody) :
        lopick(viaSecret, ['accessKey', 'secretKey']); // verified to exist
    const credentials = new aws.Credentials(via.accessKey, via.secretKey, via.sessionToken);
    return awsSession(secret, requestBody, credentials);
}

function azureSession(secret) {
    const auth = lopick(secret, cloudAllowedFields.azure);
    return {
        ...auth,
        _env: {
            AZURE_SUBSCRIPTION_ID: auth.subscriptionId,
            AZURE_TENANT_ID: auth.tenantId,
            AZURE_CLIENT_ID: auth.clientId,
            ...(auth.clientSecret ? {AZURE_CLIENT_SECRET: auth.clientSecret} : {}),
            ...(auth.clientCertificate ? {AZURE_CERTIFICATE_PATH: auth.clientCertificate} : {})
        },
        _envAsFile: auth.clientCertificate ? ['AZURE_CERTIFICATE_PATH'] : []
    };
}

function gcpSession(secret) {
    const auth = lopick(secret, cloudAllowedFields.gcp);
    return {
        ...auth,
        _env: {
            GOOGLE_APPLICATION_CREDENTIALS: JSON.stringify(auth)
        },
        _envAsFile: ['GOOGLE_APPLICATION_CREDENTIALS']
    };
}

module.exports = {
    awsSession,
    awsSessionVia,
    azureSession,
    gcpSession
};
