#!/bin/sh -e

ip=${VAULT_IP:-127.0.0.1}
port=${VAULT_PORT:-8200}
vault=${VAULT:-vault}

test -z "$VAULT_DEV_LISTEN_ADDRESS" && export VAULT_DEV_LISTEN_ADDRESS="$ip:$port"
root_token=$(uuidgen)
$vault server -dev -dev-root-token-id=$root_token &
sleep 1

export VAULT_ADDR="http://$VAULT_DEV_LISTEN_ADDRESS"
export VAULT_TOKEN=$root_token

$vault write sys/policy/authentication-service-high-priv policy=@policies/policy-auth-high.hcl
$vault write sys/policy/authentication-service-low-priv  policy=@policies/policy-auth-low.hcl
$vault write sys/policy/automation-hub-high-priv         policy=@policies/policy-hub-high.hcl
$vault write sys/policy/automation-hub-low-priv          policy=@policies/policy-hub-low.hcl

$vault secrets disable secret
$vault secrets enable -version=1 -path=secret kv
$vault auth enable approle
for role in authentication-service-high-priv \
            authentication-service-low-priv \
            automation-hub-high-priv \
            automation-hub-low-priv; do

    $vault write auth/approle/role/$role period=60m \
        bind_secret_id=false secret_id_bound_cidrs=127.0.0.0/8,10.0.0.0/8 \
        policies=$role
done

role_id_high_priv_auth=$($vault read -format=json auth/approle/role/authentication-service-high-priv/role-id |jq -r .data.role_id)
role_id_low_priv_auth=$($vault read -format=json auth/approle/role/authentication-service-low-priv/role-id |jq -r .data.role_id)
role_id_high_priv_hub=$($vault read -format=json auth/approle/role/automation-hub-high-priv/role-id |jq -r .data.role_id)
role_id_low_priv_hub=$($vault read -format=json auth/approle/role/automation-hub-low-priv/role-id |jq -r .data.role_id)

config=vault-service-roles.json
cat >$config <<EOJ
{
    "highPrivAuth": "$role_id_high_priv_auth",
    "lowPrivAuth": "$role_id_low_priv_auth",
    "highPrivHub": "$role_id_high_priv_hub",
    "lowPrivHub": "$role_id_low_priv_hub"
}
EOJ

echo "\n$config created, ^C to stop Vault"

wait
