#!/bin/sh -x

vault=${vault:-vault}

${vault} delete auth/approle/role/authentication-service-high-priv
${vault} delete auth/approle/role/authentication-service-low-priv
${vault} delete auth/approle/role/automation-hub-high-priv
${vault} delete auth/approle/role/automation-hub-low-priv

${vault} delete sys/policy/authentication-service-high-priv
${vault} delete sys/policy/authentication-service-low-priv
${vault} delete sys/policy/automation-hub-high-priv
${vault} delete sys/policy/automation-hub-low-priv

# Keep AppRole enabled to preserve roles created for Okta users
# ${vault} auth-disable approle

rm -f vault-service-roles.yaml
