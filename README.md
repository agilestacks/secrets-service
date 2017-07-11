# Secrets Service

We must store and manage user and our own secrets securely, also credentials and (IAM) roles we generate on behalf of the client.

Secrets include:

- cloud keys, service account certificates - depending on a provider;
- SSH keys, public and private;
- TLS keys and certificates, including rotation of [Let's Encrypt] issued certs;
- cross-account trust relationship roles and, optionally, keys to assume the role, and keys for the role assumed;
- admin and special-access users passwords;
- arbitrary tokens.

We'll use [Vault] as our backend, but our API will be proprietary.

Related tickets:

- [#46](https://github.com/agilestacks/control-plane/issues/46) Secrets Service design

## Design

1. For every user create a Vault policy restricting path to the specific resources (path). Policy creation is triggered at user sign-up time. A special token is used for the purpose.
2. Issue a Vault token (never expire?).
3. Save token to user profile.
4. New expiring Vault token (TTL = 1h) is created by Auth Service based on user-profile saved token and put into header `X-Secrets-Token` for backend services consumption.
5. Backend service supplies the token calling Secrets Service.
6. Token is refreshed by Auth Service / Proxy as long as user is logged in.

## Unseal

We aim to rarely restart the Vault, then unseal it manually. Deployment to Kubernetes may be problematic because container can be moved by infrastructure. Probably, use clustered Vault.


[Vault]: https://www.vaultproject.io/
[Let's Encrypt]: https://letsencrypt.org/
