const {flatten, values: lovalues} = require('lodash');
const {BadRequestError} = require('./errors');

const allowedEntities = [
    'environments',
    'cloud-accounts',
    'licenses',
    'templates',
    'instances',
    'applications',
    'service-accounts'
];
// this setup must be duplicated to ../test/api.test.js
const allowedKinds = [
    'password', 'cloudAccount', 'cloudAccessKeys', 'privateKey',
    'certificate', 'sshKey', 'usernamePassword', 'text', 'license',
    'token', 'bearerToken', 'accessToken', 'refreshToken', 'loginToken'
];
const cloudAllowedFields = {
    aws: ['accessKey', 'secretKey', 'roleArn', 'externalId', 'duration', 'region', 'sts'],
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
    'privateKey', 'certificate', 'sshKey', 'text', 'licenseKey',
    'cloud',
    ...flatten(lovalues(cloudAllowedFields))
];
const allowedClouds = ['aws', 'azure', 'gcp'];
const awsRegions = [
    'af-south-1',
    'ap-east-1',
    'ap-northeast-1',
    'ap-northeast-2',
    'ap-northeast-3',
    'ap-south-1',
    'ap-southeast-1',
    'ap-southeast-2',
    'ca-central-1',
    'cn-north-1',
    'cn-northwest-1',
    'eu-central-1',
    'eu-north-1',
    'eu-south-1',
    'eu-west-1',
    'eu-west-2',
    'eu-west-3',
    'me-south-1',
    'sa-east-1',
    'us-east-1',
    'us-east-2',
    'us-west-1',
    'us-west-2',
    'us-gov-east-1',
    'us-gov-west-1'
];
const awsStsPattern = /^https:\/\/sts(\..+)?\.amazonaws\.com$/;

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

function checkAwsCloud(secret) {
    const {region, sts} = secret;
    if (sts) {
        if (!awsStsPattern.test(sts)) {
            throw new BadRequestError(`Secret 'sts' does not match ${awsStsPattern}; got '${sts}'`);
        }
    }
    if (region) {
        if (!awsRegions.includes(region)) {
            throw new BadRequestError(`Secret 'region' not recognized; got '${region}'`);
        }
    }
}

function checkCloudKind(secret, mustBeCloudAccount = false) {
    const {kind: secretKind, cloud: cloudKind} = secret;
    if (['cloudAccount', 'cloudAccessKeys'].includes(secretKind)) {
        if (!allowedClouds.some(kind => kind === cloudKind)) {
            const error = `Secret 'cloud' must be one of '${allowedClouds.join(', ')}'; got '${cloudKind}'`;
            throw new BadRequestError(error);
        }
        if (cloudKind === 'aws') {
            checkAwsCloud(secret);
        }
    } else if (mustBeCloudAccount) {
        throw new BadRequestError('Secret is not [`cloudAccount`, `cloudAccessKeys`] kind');
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
