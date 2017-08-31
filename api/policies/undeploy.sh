#!/bin/sh -e

cwd="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

vault=${vault:-vault}
kubectl=${kubectl:-"kubectl --namespace=automation-hub"}

${kubectl} delete -f ${cwd}/vault-service-roles.yaml | true

${vault} delete auth/approle/role/authentication-service-high-priv
${vault} delete auth/approle/role/authentication-service-low-priv
${vault} delete auth/approle/role/automation-hub-high-priv
${vault} delete auth/approle/role/automation-hub-low-priv

${vault} delete sys/policy/authentication-service-high-priv
${vault} delete sys/policy/authentication-service-low-priv
${vault} delete sys/policy/automation-hub-high-priv
${vault} delete sys/policy/automation-hub-low-priv

${vault} auth-disable approle | true

rm -f ${cwd}/vault-service-roles.yaml
