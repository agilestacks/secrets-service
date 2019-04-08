function maskRole(roleArn) {
    const c = roleArn.split(':', 6);
    if (c.length >= 6) {
        const roleName = c[5];
        c[5] = roleName.substring(0, 9).padEnd(roleName.length, '*');
        return c.join(':');
    }
    return roleArn.substring(0, 26).padEnd(roleArn.length, '*');
}

function maskExternalId(externalId) {
    const truncAt = Math.min(externalId.length, 10) - 2;
    return externalId.substr(0, truncAt).padEnd(externalId.length, '*');
}

function maskKey(key) {
    const truncAt = key.startsWith('AK') ? 8 : 4;
    return key.substring(0, truncAt).padEnd(key.length, '*');
}

function maskPem(pem) {
    const truncAt = pem.indexOf('\n');
    if (truncAt > 0) return pem.substring(0, truncAt);
    return pem;
}

function maskSecrets(secret) {
    const masked = {...secret};
    if (secret.kind === 'cloudAccount') {
        switch (secret.cloud) {
        case 'aws':
            if (masked.roleArn) masked.roleArn = maskRole(masked.roleArn);
            if (masked.externalId) masked.externalId = maskExternalId(masked.externalId);
            if (masked.accessKey) masked.accessKey = maskKey(masked.accessKey);
            if (masked.secretKey) masked.secretKey = maskKey(masked.secretKey);
            break;
        case 'azure':
            if (masked.clientSecret) masked.clientSecret = maskKey(masked.clientSecret);
            if (masked.clientCertificate) masked.clientCertificate = maskPem(masked.clientCertificate);
            break;
        case 'gcp':
            if (masked.client_secret) masked.client_secret = maskKey(masked.client_secret);
            if (masked.refresh_token) masked.refresh_token = maskKey(masked.refresh_token);
            if (masked.private_key) masked.private_key = maskPem(masked.private_key);
            break;
        default:
        }
    }
    return masked;
}

module.exports = {
    maskSecrets,
    maskRole,
    maskExternalId,
    maskKey
};
