# Secrets Service

We must store and manage user and our own secrets securely, also credentials and (IAM) roles we generate on behalf of the client.

Secrets include:

- cloud keys, service account certificates - depending on a provider;
- SSH keys, public and private;
- TLS keys and certificates, including rotation of [Let's Encrypt] issued certs;
- cross-account trust relationship roles and, optionally, keys to assume the role, and keys for the role assumed;
- admin and special-access users passwords;
- arbitrary tokens.

We'll use [Vault] as our backend, but our HTTP-based [API] will be proprietary.

## Design

1. For every user create a Vault policy restricting path to the specific resources (path). Policy creation is triggered at user sign-up time. A special token is used for the purpose.
2. Issue a Vault token (never expire?).
3. Save token to user profile.
4. New expiring Vault token (TTL = 1h) is created by Auth Service based on user-profile saved token and put into header `X-Secrets-Token` for backend services consumption.
5. Backend service supplies the token when calling Secrets Service.
6. Token is refreshed by Auth Service / Proxy as long as user is logged in.

## Schema

User is a member of multiple Teams. Multiple Teams has access to Environment with corresponding permissions: Read, Write, Admin.

Secrets belongs to Environment and Secret has a `name` (which is optional), `kind`, and an `id`. Secret path is: `/api/v1/environments/<environment id>/secrets/<secret id>`. Where `/api/v1` is standard prefix for all HTTP requests. `secret id` is UUID that is .

### Secret kind

Currently supported secret kinds are:

1. `password`
2. `cloudAccount`

Password is an arbitrary string that is written and read as is.

Cloud account is either a pair of AWS access/secret keys or a role name that can be assumed to access customer's account. The role is assumed by empty AgileStacks account to retrieve temporary credentials: access and secret keys with session token. In both cases only temporary credentials could be read from Secrets Service. Reading cloud account entity returns original security-sensitive information masked.

Password:

```json
{
    "id": "02a669c0-543b-432f-a11d-fb21f29c7200",
    "name": "component.postgresql.password",
    "kind": "password",
    "value": "qwerty"
}
```

Cloud account entity:

```json
{
    "id": "4ae21e5e-c49f-4222-b164-ffb03d8448dd",
    "name": "My AWS",
    "kind": "cloudAccount",
    "cloud": "aws",
    "accessKey": "AKIA****************",
    "secretKey": "qwerty**********************************"
}
```

```json
{
    "id": "4ae21e5e-c49f-4222-b164-ffb03d8448dd",
    "name": "My AWS",
    "kind": "cloudAccount",
    "cloud": "aws",
    "roleArn": "arn:aws:iam::973998981304:role/xaccount-*********************"
}
```

Cloud account temporary credentials for AWS:

```json
{
    "accessKey": "AKIA****************",
    "secretKey": "qwerty**********************************",
    "sessionToken": "..."
}
```

## HTTP Methods

`GET` - retrieve secret by `id` via `/api/v1/environments/<environment id>/secrets/<secret id>`. Session keys are retrieved via `.../<secret id>/session-keys`.

`POST` - create a secret at `/api/v1/environments/<environment id>/secrets`. UUID `id` is returned and `Location` HTTP header is served.

`PUT` - update secret by `id`.

`DELETE` - delete secret by `id`.

## Usage

To retrieve a secret from Secrets Service in Automation Hub API service (for example) get the authentication token from `X-Secrets-Token` HTTP header. Use the token to send the same `X-Secrets-Token` header to Secrets Service.

## Authentication Proxy

The `X-Secrets-Token` HTTP header for backend services is enriched by Authentication Proxy (see [auth-service/issues/3](https://github.com/agilestacks/auth-service/issues/3)). Upon login Authentication Service request a new temporary Vault token from Secrets Service. It uses a permanent user-specific token saved at user creation time in user Okta profile. Permanent token is also requested from Secrets Service using high-privilege token configured in Authentication Service environment (pod/container).

## Policy

Every Control Plane user has a permanent Vault token issued and saved into Okta profile. A policy associated with the token restricts user access to secrets bound to Environments user has access to (via team membership).

### Policy path restrictions

For every Environment user has access to an entry is added to user's (token) Vault policy, for example:

```hcl
path "secret/environments/<environment id>/secrets/*" {
  capabilities = ["create", "read", "update", "delete"]
}
```

### Policy change triggers

Policy must be regenerated and updated on each change to Team membership and Team permissions change on Environment. 

#### User

When user is created a new token is issued and empty policy is created.

#### Team membership

User policy must be regenerated and saved when team membership is updated.

#### Environment permissions

Team's users policies must be regenerated and saved when team permissions on Environment is changed (added, and revoked).

#### API

To update Vault policy use high-privilege token. Path to the entity that maps to Vault policy is `/api/v1/tokens/<token>/environments`:

```json
{
    "environments": ["env id 1", "env id 2", ...]
}
```

## Unseal

We aim to rarely restart the Vault, then unseal it manually. Deployment to Kubernetes may be problematic because container can be moved by infrastructure. Probably, use clustered Vault.


[API]: https://agilestacks.github.io/secrets-service/API.html
[Vault]: https://www.vaultproject.io/
[Let's Encrypt]: https://letsencrypt.org/
