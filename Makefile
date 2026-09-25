ENVTEST_K8S_VERSION ?= 1.35.0
GOBIN ?= $(shell go env GOPATH)/bin
IMG ?= site-operator:latest

.PHONY: generate manifests test build docker-build render

generate: ## deepcopy
	$(GOBIN)/controller-gen object paths=./api/...

manifests: ## Site CRD
	$(GOBIN)/controller-gen crd paths=./api/v1alpha1/... output:crd:artifacts:config=config/crd/bases

test: generate manifests
	go vet ./...
	KUBEBUILDER_ASSETS="$$($(GOBIN)/setup-envtest use -p path $(ENVTEST_K8S_VERSION))" go test ./...

build:
	go build -o bin/site-operator ./cmd

docker-build:
	docker build -t $(IMG) .

render:
	kubectl kustomize config/default
