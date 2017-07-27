.DEFAULT_GOAL := test

.DEFAULT_GOAL := lint

export AWS_ACCOUNT_NUMBER ?= 973998981304
export TF_VAR_name        ?= dev
export AWS_DEFAULT_REGION ?= us-east-2
export IMAGE              ?= $(AWS_ACCOUNT_NUMBER).dkr.ecr.$(AWS_DEFAULT_REGION).amazonaws.com/agilestacks/$(TF_VAR_name)/secrets-service
export IMAGE_NAME         ?= $(IMAGE):$(IMAGE_VERSION)
export IMAGE_VERSION      ?= $(shell git rev-parse HEAD | colrm 7)
export IMAGE_NAME_LATEST  ?= $(IMAGE):latest
export DOMAIN_NAME        ?= $(TF_VAR_name).$(TF_VAR_base_domain)
export NAMESPACE          ?= automation-hub
export kubectl            ?= kubectl --context="$(DOMAIN_NAME)" --namespace="$(NAMESPACE)"

build:
	@git rev-parse HEAD | colrm 7 > rev.txt
	@docker build -t $(IMAGE_NAME) .
.PHONY: build

push:
	aws ecr get-login --region $(AWS_DEFAULT_REGION) | sed -e 's/[ +]-e[ +]none[ +]/ /g' | sh -
	docker tag  $(IMAGE_NAME) $(IMAGE_NAME_LATEST)
	docker push $(IMAGE_NAME)
	docker push $(IMAGE_NAME_LATEST)
.PHONY: push

deploy: build push
	$(kubectl) apply -f templates/service.yaml
	$(kubectl) apply -f templates/deployment.yaml
.PHONY: deploy

undeploy:
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

vault-test-setup:
	@bin/vault-test-setup.sh
.PHONY: vault-test
