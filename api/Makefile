.DEFAULT_GOAL := test

.DEFAULT_GOAL := lint

export AWS_DEFAULT_REGION ?= us-east-2
export TF_VAR_name        ?= dev
export TF_VAR_base_domain ?= stack.delivery
export REGISTRY           ?= $(subst https://,,$(lastword $(shell aws ecr get-login --region $(AWS_DEFAULT_REGION))))
export IMAGE              ?= $(REGISTRY)/agilestacks/$(TF_VAR_name)/secrets-service
export IMAGE_VERSION      ?= $(shell git rev-parse HEAD | colrm 7)
export NAMESPACE          ?= automation-hub
export kubectl            ?= kubectl --context="$(TF_VAR_name).$(TF_VAR_base_domain)" --namespace="$(NAMESPACE)"

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
	$(kubectl) delete -f templates/deployment.yaml | true
	$(kubectl) delete -f templates/service.yaml    | true
	$(kubectl) delete -f templates/namespace.yaml  | true
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
