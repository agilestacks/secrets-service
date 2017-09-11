.DEFAULT_GOAL := test

.DEFAULT_GOAL := lint

export AWS_DEFAULT_REGION ?= us-east-2
export TF_VAR_name        ?= dev
export TF_VAR_base_domain ?= stack.delivery
export REGISTRY           ?= $(subst https://,,$(lastword $(shell aws ecr get-login --region $(AWS_DEFAULT_REGION))))
export IMAGE              ?= $(REGISTRY)/agilestacks/$(TF_VAR_name)/secrets-service
export IMAGE_VERSION      ?= $(shell git rev-parse HEAD | colrm 7)
export NAMESPACE          ?= automation-hub
export kubectl            ?= kubectl --context=$(TF_VAR_name).$(TF_VAR_base_domain) --namespace=$(NAMESPACE)
export VPC_CIDR           ?= 10.0.0.0/16

export VAULT_LOCAL_PORT   := 31321
export VAULT_ADDR         := http://127.0.0.1:$(VAULT_LOCAL_PORT)

VAULT_COMPONENT_SOURCE_DIR ?= ../../components/vault

build:
	@docker build -t $(IMAGE):$(IMAGE_VERSION) .
.PHONY: build

push:
	aws ecr get-login --region $(AWS_DEFAULT_REGION) | sed -e 's/[ +]-e[ +]none[ +]/ /g' | sh -
	docker tag  $(IMAGE):$(IMAGE_VERSION) $(IMAGE):latest
	docker push $(IMAGE):$(IMAGE_VERSION)
	docker push $(IMAGE):latest
.PHONY: push

deploy: build push vault-connect policies-deploy vault-disconnect
	$(kubectl) apply -f templates/namespace.yaml
	$(kubectl) apply -f templates/service.yaml
	$(kubectl) apply -f templates/deployment.yaml
	$(MAKE) output
.PHONY: deploy

undeploy: vault-connect policies-undeploy vault-disconnect
	$(kubectl) delete -f templates/deployment.yaml | true
	$(kubectl) delete -f templates/service.yaml    | true
.PHONY: undeploy

install:
	@npm install
.PHONY: install

lint:
	@npm run lint
.PHONY: test

test:
	@npm test
.PHONY: test

run:
	@npm start
.PHONY: run

vault-connect:
	@cd $(VAULT_COMPONENT_SOURCE_DIR) && $(MAKE) connect auth
.PHONY: vault-connect

vault-disconnect:
	cd $(VAULT_COMPONENT_SOURCE_DIR) && $(MAKE) disconnect
.PHONY: vault-disconnect

policies-deploy:
	@echo "Bootstrap Vault roles"
	$(SHELL) -e policies/deploy.sh
.PHONY: policies-deploy

policies-undeploy:
	@echo "Delete Vault roles"
	$(SHELL) policies/undeploy.sh
.PHONY: policies-undeploy


vault-test-setup:
	@bin/vault-test-setup.sh
.PHONY: vault-test


output:
	@echo Outputs:
	@echo app_roles_secret=vault-service-roles
.PHONY: output
