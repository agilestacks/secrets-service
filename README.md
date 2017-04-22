# Secrets Service

We must store and manage user and our own secrets securely, also credentials and (IAM) roles we generate on behalf of the client.

Secrets include:

- cloud keys, service account certificates - depending on a provider;
- SSH keys, public and private;
- TLS keys and certificates, including rotation of [Let's Encrypt] issued certs.
- cross-account trust relationship roles and, optionally, keys to assume the role;
- admin and special-access users passwords;
- arbitrary tokens.

We'll use [Vault] as our backend, but our API will be proprietary.

Related tickets:

- [#46](https://github.com/agilestacks/control-plane/issues/46) Secrets service design

[Vault]: https://www.vaultproject.io/
[Let's Encrypt]: https://letsencrypt.org/
