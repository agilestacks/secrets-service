#!/bin/sh -xe

vault=${vault:-vault}
VAULT_ADDR=${VAULT_ADDR:-"http://127.0.0.1:8200"}
SERVICES_CIDR=${SERVICES_CIDR:-"10.0.0.0/8"}
NAMESPACE=${NAMESPACE:-automation-hub}
KUBERNETES_SECRET_NAME=${KUBERNETES_SECRET_NAME:-vault-service-roles}

# Create Policies
${vault} write sys/policy/authentication-service-high-priv policy=@policy-auth-high.hcl
${vault} write sys/policy/authentication-service-low-priv  policy=@policy-auth-low.hcl
${vault} write sys/policy/automation-hub-high-priv         policy=@policy-hub-high.hcl
${vault} write sys/policy/automation-hub-low-priv          policy=@policy-hub-low.hcl

# Enable AppRole authentication
${vault} auth enable approle || true

# Create Roles
for role in authentication-service-high-priv \
            authentication-service-low-priv \
            automation-hub-high-priv \
            automation-hub-low-priv; do

    ${vault} write auth/approle/role/${role} period=60m \
        bind_secret_id=false bound_cidr_list=127.0.0.0/8,172.17.0.0/16,${SERVICES_CIDR} \
        policies=${role}

    role_id=$(echo $role | tr - _)
    eval ${role_id}=$(${vault} read -format=json auth/approle/role/$role/role-id | jq -r .data.role_id | tr -d '\n' | base64)
done

cat >vault-service-roles.yaml <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: ${KUBERNETES_SECRET_NAME}
  namespace: ${NAMESPACE}
  labels:
    provider: agilestacks.com
    project:  secrets-service
data:
  role_id_high_priv_auth: ${authentication_service_high_priv}
  role_id_low_priv_auth: ${authentication_service_low_priv}
  role_id_high_priv_hub: ${automation_hub_high_priv}
  role_id_low_priv_hub: ${automation_hub_low_priv}
EOF
