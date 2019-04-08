const {flatten, values: lovalues} = require('lodash');
const {BadRequestError} = require('./errors');

const allowedEntities = ['environments', 'cloud-accounts', 'licenses', 'templates', 'instances', 'service-accounts'];
const allowedKinds = [
    'password', 'cloudAccount', 'cloudAccessKeys', 'privateKey',
    'certificate', 'sshKey', 'usernamePassword', 'text', 'license',
    'token', 'bearerToken', 'accessToken', 'refreshToken', 'loginToken'
];
const cloudAllowedFields = {
    aws: ['accessKey', 'secretKey', 'roleArn', 'externalId', 'duration'],
    azure: [
        'clientId',
        'clientSecret', 'clientCertificate',
        'subscriptionId', 'tenantId',
        'activeDirectoryEndpointUrl', 'resourceManagerEndpointUrl', 'activeDirectoryGraphResourceId',
        'sqlManagementEndpointUrl', 'galleryEndpointUrl', 'managementEndpointUrl'
    ],
    gcp: [
        'type',
        // authorized_user
        'client_id', 'client_secret', 'refresh_token',
        // service_account
        'project_id',
        'private_key_id', 'private_key', 'client_email', 'client_id',
        'auth_uri', 'token_uri', 'auth_provider_x509_cert_url', 'client_x509_cert_url'
    ]
};
const allowedFields = [
    'name', 'kind',
    'userId', 'userName', 'groupId', 'groupName',
    'username', 'password', 'token', 'bearerToken', 'accessToken', 'refreshToken', 'loginToken',
    'cloud',
    ...flatten(lovalues(cloudAllowedFields))
];
const allowedClouds = ['aws', 'azure', 'gcp'];

function checkEntityKind(entityKind) {
    if (!allowedEntities.some(kind => kind === entityKind)) {
        const error = `Entity must be one of '${allowedEntities.join(', ')}'; got '${entityKind}'`;
        throw new BadRequestError(error);
    }
}

function checkSecretKind(secretKind) {
    if (!allowedKinds.some(kind => kind === secretKind)) {
        const error = `Secret 'kind' must be one of '${allowedKinds.join(', ')}'; got '${secretKind}'`;
        throw new BadRequestError(error);
    }
}

function checkCloudKind(secretKind, cloudKind, mustBeCloudAccount = false) {
    if (secretKind === 'cloudAccount') {
        if (!allowedClouds.some(kind => kind === cloudKind)) {
            const error = `Secret 'cloud' must be one of '${allowedClouds.join(', ')}'; got '${cloudKind}'`;
            throw new BadRequestError(error);
        }
    } else if (mustBeCloudAccount) {
        throw new BadRequestError('Secret is not `cloudAccount` kind');
    }
}

module.exports = {
    allowedEntities,
    allowedFields,
    allowedClouds,
    cloudAllowedFields,
    checkEntityKind,
    checkSecretKind,
    checkCloudKind
};
