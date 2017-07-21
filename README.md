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

1. For every user create a Vault _policy_ restricting path to specific resources (secrets, by path) and basic _token_ manipulation - renewal and revocation only. Policy creation is triggered at user sign-up time. A high-privilege token owned by Authentication Service (users CRUD) is used for the purpose. The token is obtained via AppRole Vault Auth Backend. Policy is updated using the same token when Team membership or Environment permissions changes.
2. Issue a Vault AppRole `role_id` specific to the user and associate the policy. Include no `default` policy.
3. Save `role_id` to user profile (in Okta).
4. On user login, an expiring Vault token (TTL = 1h) is requested by Authentication Service from Secrets Service supplying saved `role_id`. The request is enriched with the obtained token added into `X-Secrets-Token` HTTP header for backend services consumption. Secrets Service low-privilege token is used to `pull` `secret_id` from the role and do AppRole login to obtain token for the user.
5. Backend service supplies the token when calling Secrets Service in `X-Secrets-Token` header.
6. Token is refreshed by Authentication Service / Proxy every 30 min as long as user is logged in.
7. Token is revoked by Authentication Service on logout.

## Schema

User is a member of multiple Teams. Multiple Teams have access to Environment with corresponding permissions: Read, Write, Admin.

Secrets belongs to Environment and Secret has a `name` (which is optional), `kind`, and an `id`. Secret path is: `/api/v1/environments/<environment id>/secrets/<secret id>`. Where `/api/v1` is standard prefix for all HTTP requests. `secret id` is UUID that is returned by Secrets Service when secret is created (`POST`) and is saved as a reference by the calling service.

### Secret kind

Currently supported secret kinds are:

1. `password`, optionally with `username`
2. `cloudAccount`

Password / username are arbitrary strings that are written and read as is.

Cloud account is either (1) a pair of AWS access/secret keys or (2) a role name that can be assumed to access customer's AWS account. The role is assumed by empty AgileStacks AWS account to retrieve temporary credentials: access and secret keys with session token. In both cases only temporary credentials could be read from Secrets Service. Reading cloud account entity returns original security-sensitive information masked.

Password:

```json
{
    "id": "02a669c0-543b-432f-a11d-fb21f29c7200",
    "name": "component.postgresql.password",
    "kind": "password",
    "username": "asdf",
    "password": "qwerty"
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

Cloud account temporary credentials for AWS obtained via STS or AssumeRole:

```json
{
    "accessKey": "AKIA****************",
    "secretKey": "qwerty**********************************",
    "sessionToken": "..."
}
```

The TTL is 1 hour.

## HTTP Methods

`GET` - retrieve secret by `id` via `/api/v1/environments/<environment id>/secrets/<secret id>`. Session keys are retrieved via `.../<secret id>/session-keys`.

`POST` - create a secret at `/api/v1/environments/<environment id>/secrets`. UUID `id` is returned and `Location` HTTP header is served.

`PUT` - update secret by `id`.

`DELETE` - delete secret by `id`.

## Usage

To retrieve a secret from Secrets Service (in Automation Hub API service, for example) get the authentication token from `X-Secrets-Token` HTTP header. Use the token to send the same `X-Secrets-Token` header to Secrets Service.

## Authentication Proxy

The `X-Secrets-Token` HTTP header for backend services is enriched by Authentication Proxy (see [auth-service/issues/3](https://github.com/agilestacks/auth-service/issues/3)). Upon login Authentication Service request an expiring Vault token from Secrets Service. It supplies permanent `role_id` saved at user creation time in user Okta profile.

## Policy

Every Control Plane user has a permanent Vault AppRole `role_id` issued and saved into Okta profile. A policy associated with the role restricts user access to secrets bound to Environments user has access to (via team membership).

### Policy path restrictions

For every Environment user has access to an entry is added to user's Vault policy associated to the role, for example:

```hcl
path "secret/environments/<environment id>/secrets/*" {
  capabilities = ["create", "read", "update", "delete"]
}

path "secret/environments/env-1/secrets/*" {
  capabilities = ["create", "read", "update", "delete"]
}

path "secret/environments/env-2/secrets/*" {
  capabilities = ["create", "read", "update", "delete"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}

path "auth/token/revoke-self" {
  capabilities = ["update"]
}
```

### Policy change triggers

Policy must be regenerated and updated on each change to Team membership and Team permissions change on Environment. 

#### User

When user is created a new `role_id` is issued and empty policy is created.

#### Team membership

User policy must be regenerated and saved when team membership is updated.

#### Environment permissions

Team's users policies must be regenerated and saved when team permissions on Environment is changed (added, and revoked).

#### API

To create new user `PUT` into `/api/v1/users/<okta user id>`. Vault `role_id` is returned:

```json
{
    "roleId": "0dcc3856-c11b-9673-bd30-b083cbae4987"
}
```

To update Vault policy use `PUT` with high-privilege token. Path to the entity that maps to Vault policy is `/api/v1/users/<okta user id>/environments`:

```json
{
    "environments": ["env id 1", "env id 2", ...]
}
```

At user login use `POST` with low-privilege token to get token for the user from `/api/v1/login`:

```json
{
    "roleId": "0dcc3856-c11b-9673-bd30-b083cbae4987"
}
```

Expiring token is returned:

```json
{
    "token": "c9086cfc-c1a4-4609-546d-1f9d860c8ac3"
}
```

Every 30 min refresh the token by `POST` with user token into `/api/v1/renew`. And revoke token via `/api/v1/revoke`.

## Unseal

We aim to rarely restart the Vault, then unseal it manually. Deployment to Kubernetes may be problematic because container can be moved by infrastructure. Probably, use clustered Vault.


[API]: https://agilestacks.github.io/secrets-service/API.html
[Vault]: https://www.vaultproject.io/
[Let's Encrypt]: https://letsencrypt.org/
