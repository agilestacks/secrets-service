.DEFAULT_GOAL := deploy

export DOMAIN_NAME ?= dev.stack.delivery
export NAMESPACE   ?= automation-hub
export kubectl     ?= kubectl --context=$(DOMAIN_NAME) --namespace=$(NAMESPACE)

export VAULT_LOCAL_PORT := 31321
export VAULT_ADDR       := http://127.0.0.1:$(VAULT_LOCAL_PORT)

VAULT_COMPONENT_NAME ?= vault

deploy: vault-connect policies-deploy vault-disconnect create-kubernetes-secret
.PHONY: deploy

undeploy: delete-kubernetes-secret vault-connect policies-undeploy vault-disconnect
.PHONY: undeploy

vault-connect:
	$(HUB) invoke $(VAULT_COMPONENT_NAME) connect
	$(HUB) invoke $(VAULT_COMPONENT_NAME) login
.PHONY: vault-connect

vault-disconnect:
	$(HUB) invoke $(VAULT_COMPONENT_NAME) disconnect
.PHONY: vault-disconnect

policies-deploy:
	@echo "Bootstraping Vault App Roles"
	./create.sh
.PHONY: policies-deploy

policies-undeploy:
	@echo "Deleting Vault App Roles"
	./delete.sh
.PHONY: policies-undeploy

create-kubernetes-secret:
	$(kubectl) apply -f namespace.yaml
	${kubectl} apply -f vault-service-roles.yaml
.PHONY: create-kubernetes-secret

delete-kubernetes-secret:
	-${kubectl} delete -f vault-service-roles.yaml
.PHONY: delete-kubernetes-secret
