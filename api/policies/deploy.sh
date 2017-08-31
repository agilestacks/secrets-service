#!/bin/sh -ex

VAULT_ADDR=${VAULT_ADDR:-"http://127.0.0.1:8200"}

cwd="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
vault=${vault:-vault}

NAMESPACE=${NAMESPACE:=automation-hub}
kubectl=${kubectl:-kubectl --namespace=$NAMESPACE}

VPC_CIDR=${VPC_CIDR:-10.0.0.0/16}

${vault} write sys/policy/authentication-service-high-priv rules=@${cwd}/policy-auth-high.hcl
${vault} write sys/policy/authentication-service-low-priv  rules=@${cwd}/policy-auth-low.hcl
${vault} write sys/policy/automation-hub-high-priv         rules=@${cwd}/policy-hub-high.hcl
${vault} write sys/policy/automation-hub-low-priv          rules=@${cwd}/policy-hub-low.hcl
${vault} auth-enable approle | true

# $vault auth-enable approle
for role in authentication-service-high-priv \
            authentication-service-low-priv \
            automation-hub-high-priv \
            automation-hub-low-priv; do

    ${vault} write auth/approle/role/${role} period=60m \
        bind_secret_id=false bound_cidr_list=127.0.0.0/8,${VPC_CIDR} \
        policies=${role}
done

role_id_high_priv_auth=$(${vault} read -format=json auth/approle/role/authentication-service-high-priv/role-id |jq -Mr .data.role_id | base64)
role_id_low_priv_auth=$(${vault} read -format=json auth/approle/role/authentication-service-low-priv/role-id |jq -Mr .data.role_id | base64)
role_id_high_priv_hub=$(${vault} read -format=json auth/approle/role/automation-hub-high-priv/role-id |jq -Mr .data.role_id | base64)
role_id_low_priv_hub=$(${vault} read -format=json auth/approle/role/automation-hub-low-priv/role-id |jq -Mr .data.role_id | base64)

cat >${cwd}/vault-service-roles.yaml <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: vault-service-roles
  namespace: automation-hub
  labels:
    provider: agilestacks.com
    project:  secrets-service
data:
  role_id_high_priv_auth: ${role_id_high_priv_auth}
  role_id_low_priv_auth: ${role_id_low_priv_auth}
  role_id_high_priv_hub: ${role_id_high_priv_hub}
  role_id_low_priv_hub: ${role_id_low_priv_hub}
EOF

${kubectl} apply -f ${cwd}/vault-service-roles.yaml
