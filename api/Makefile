.DEFAULT_GOAL := lint

export AWS_DEFAULT_REGION ?= us-east-2
export TF_VAR_name        ?= dev
export TF_VAR_base_domain ?= stack.delivery
export REGISTRY           ?= $(subst https://,,$(lastword $(shell aws ecr get-login --region $(AWS_DEFAULT_REGION))))
export IMAGE              ?= $(REGISTRY)/agilestacks/$(TF_VAR_name)/secrets-service
export IMAGE_VERSION      ?= $(shell git rev-parse HEAD | colrm 7)
export NAMESPACE          ?= automation-hub
export kubectl            ?= kubectl --context=$(TF_VAR_name).$(TF_VAR_base_domain) --namespace=$(NAMESPACE)
export telepresence       ?= telepresence -s secrets-service --context $(TF_VAR_name).$(TF_VAR_base_domain) --namespace $(NAMESPACE) --expose 3002

build:
	@docker build -t $(IMAGE):$(IMAGE_VERSION) .
.PHONY: build

push:
	aws ecr get-login --region $(AWS_DEFAULT_REGION) | sed -e 's/[ +]-e[ +]none[ +]/ /g' | sh -
	docker tag  $(IMAGE):$(IMAGE_VERSION) $(IMAGE):latest
	docker push $(IMAGE):$(IMAGE_VERSION)
	docker push $(IMAGE):latest
.PHONY: push

deploy: build push
	$(kubectl) apply -f templates/namespace.yaml
	$(kubectl) apply -f templates/service.yaml
	$(kubectl) apply -f templates/deployment.yaml
.PHONY: deploy

undeploy:
	-$(kubectl) delete -f templates/deployment.yaml
	-$(kubectl) delete -f templates/service.yaml
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

vault-test-setup:
	@bin/vault-test-setup.sh
.PHONY: vault-test

run-telepresence:
	$(telepresence) --run npm start
.PHONY: run-telepresence

debug-telepresence:
	$(telepresence) --run npm run debug
.PHONY: debug-telepresence
