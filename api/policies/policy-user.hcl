path "secret/environments/env-1/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "secret/environments/env-2/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}

path "auth/token/revoke-self" {
  capabilities = ["update"]
}
