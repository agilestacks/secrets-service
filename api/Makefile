.DEFAULT_GOAL := lint

export AWS_DEFAULT_REGION ?= us-east-2

DOMAIN_NAME   ?= test.dev.superhub.io
REGISTRY      ?= $(shell $(aws) sts get-caller-identity | jq -r .Account).dkr.ecr.$(AWS_DEFAULT_REGION).amazonaws.com
IMAGE         ?= $(REGISTRY)/agilestacks/$(DOMAIN_NAME)/secrets-service
IMAGE_VERSION ?= $(shell git rev-parse HEAD | colrm 7)
NAMESPACE     ?= automation-hub

kubectl       ?= kubectl --context=$(DOMAIN_NAME) --namespace=$(NAMESPACE)
telepresence  ?= telepresence -s secrets-service --context $(DOMAIN_NAME) --namespace $(NAMESPACE) --expose 3002
docker        ?= docker
aws           ?= aws

build:
	@ $(docker) build -t $(IMAGE):$(IMAGE_VERSION) .
.PHONY: build

push:
	$(aws) ecr get-login-password --region $(AWS_DEFAULT_REGION) | $(docker) login --username AWS --password-stdin $(REGISTRY)
	$(docker) tag  $(IMAGE):$(IMAGE_VERSION) $(IMAGE):latest
	$(docker) push $(IMAGE):$(IMAGE_VERSION)
	$(docker) push $(IMAGE):latest
.PHONY: push

deploy: build push
	- $(kubectl) create namespace $(NAMESPACE)
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
.PHONY: lint

test:
	@npm test
.PHONY: test

run:
	@npm start
.PHONY: run

vault-test-setup:
	@bin/vault-test-setup.sh
.PHONY: vault-test-setup

run-telepresence:
	$(telepresence) --run npm start
.PHONY: run-telepresence

debug-telepresence:
	$(telepresence) --run npm run debug
.PHONY: debug-telepresence
