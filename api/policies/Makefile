.DEFAULT_GOAL := deploy

export DOMAIN_NAME ?= dev.stack.delivery
export NAMESPACE   ?= automation-hub
export kubectl     ?= kubectl --context=$(DOMAIN_NAME) --namespace=$(NAMESPACE)

export VAULT_LOCAL_PORT := 31321
export VAULT_ADDR       := http://127.0.0.1:$(VAULT_LOCAL_PORT)

VAULT_COMPONENT_NAME   ?= vault
KUBERNETES_SECRET_NAME ?= vault-service-roles

ifeq ($(VAULT_APP_ROLES_INITIALIZED),true)
deploy: render-kubernetes-secret create-kubernetes-secret
else
deploy: vault-connect policies-deploy vault-disconnect create-kubernetes-secret
endif
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

# TODO adjust secret name and namespace
render-kubernetes-secret:
	$(HUB) render restore/vault-service-roles.yaml.template
	rm -f vault-service-roles.yaml
	mv restore/vault-service-roles.yaml .
.PHONY: policies-deploy

backup:
	$(kubectl) get secret $(KUBERNETES_SECRET_NAME)
	@echo Outputs:
	@echo component.secrets-service.app-roles.initialized = true
	@echo component.secrets-service.app-roles.secret = $$($(kubectl) get secret $(KUBERNETES_SECRET_NAME) -o yaml | base64)
	@echo
.PHONY: backup
