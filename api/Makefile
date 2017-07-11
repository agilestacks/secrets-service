.DEFAULT_GOAL := test

export AWS_ACCOUNT_NUMBER ?= 973998981304
export TF_VAR_name        ?= dev
export AWS_DEFAULT_REGION ?= us-east-2
export IMAGE              ?= $(AWS_ACCOUNT_NUMBER).dkr.ecr.$(AWS_DEFAULT_REGION).amazonaws.com/agilestacks/$(TF_VAR_name)/secrets-service
export IMAGE_NAME         ?= $(IMAGE):$(IMAGE_VERSION)
export IMAGE_VERSION      ?= $(shell git rev-parse HEAD | colrm 7)
export IMAGE_NAME_LATEST  ?= $(IMAGE):latest
export kubectl            ?= kubectl --context="$(DOMAIN_NAME)" --namespace="$(NAMESPACE)"
export PATH               := $(PATH):$(abspath ../etc)

export DOMAIN_NAME        ?= $(TF_VAR_name).$(TF_VAR_base_domain)
export NAMESPACE          ?= secrets-service
export INGRESS_PREFIX     := secrets-service
export INGRESS_FQDN       := $(INGRESS_PREFIX).app.$(DOMAIN_NAME)
export INGRESS_PATH       := /
export DEPLOYMENT_NAME    ?= secrets-service
export SERVICE_NAME       ?= secrets-service

build:
	@docker build -t $(IMAGE_NAME) .
.PHONY: build

push:
	aws ecr get-login --region $(AWS_DEFAULT_REGION) | sh -
	docker tag  $(IMAGE_NAME) $(IMAGE_NAME_LATEST)
	docker push $(IMAGE_NAME)
	docker push $(IMAGE_NAME_LATEST)
.PHONY: push

deploy:
	@templater.sh kubernetes/templates/service.yaml    | $(kubectl) apply -f -
	@templater.sh kubernetes/templates/ingress.yaml    | $(kubectl) apply -f -
	@templater.sh kubernetes/templates/deployment.yaml | $(kubectl) apply -f -
.PHONY: deploy

deploy-test:
	@echo "Secrets Service deploying"
	@sleep 1
	@echo "Secrets Service deployed"
	@sleep 1

undeploy:
	@templater.sh kubernetes/templates/service.yaml    | $(kubectl) delete -f - | cat
	@templater.sh kubernetes/templates/ingress.yaml    | $(kubectl) delete -f - | cat
	@templater.sh kubernetes/templates/deployment.yaml | $(kubectl) delete -f - | cat
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

