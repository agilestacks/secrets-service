# Secrets service

Secrets service implements Secrets [API](../API.md).

## Tests

Install dependencies:

    $ npm install

Start Vault:

    $ make vault-test-setup

Start server:

    $ make clean && npm start

Run Dredd and Jest tests:

    $ npm test
