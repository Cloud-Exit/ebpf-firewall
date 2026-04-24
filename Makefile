.PHONY: test build docker-build helm-lint helm-template e2e-kind clean

IMAGE ?= ebpf-allowlist-firewall:dev
HELM_RELEASE ?= ebpf-firewall
HELM_CHART ?= charts/ebpf-firewall
HELM_NAMESPACE ?= ebpf-firewall

test:
	go test ./...

build:
	go build ./cmd/ebpf-firewall

docker-build:
	docker build -t $(IMAGE) .

helm-lint:
	helm lint $(HELM_CHART)

helm-template:
	helm template $(HELM_RELEASE) $(HELM_CHART) --namespace $(HELM_NAMESPACE)

e2e-kind:
	./test/e2e/kind.sh

clean:
	rm -f ebpf-firewall
