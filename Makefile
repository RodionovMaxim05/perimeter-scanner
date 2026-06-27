SHELL := /bin/sh

GOBIN := $(shell go env GOPATH)/bin

GOIMPORTS := $(GOBIN)/goimports
GOLANGCI_LINT := $(GOBIN)/golangci-lint

GOLANGCI_LINT_VERSION := v2.12.2

.PHONY: fmtcheck lint tools test-integration test-unit test

fmtcheck:
	@files="$$($(GOIMPORTS) -l .)"; \
	if [ -n "$$files" ]; then \
		echo "Files need formatting:"; \
		echo "$$files"; \
		exit 1; \
	fi

lint:
	$(GOLANGCI_LINT) run --timeout=2m -E gocritic -v ./...

tools:
	go install golang.org/x/tools/cmd/goimports@latest
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

test-integration:
	# 1. Starting Postgres in the background.
	docker compose -f tests/integration/docker-compose.test.yml up -d postgres
	# 2. Launching the migrator.
	docker compose -f tests/integration/docker-compose.test.yml run --rm migrator
	# 3. Launching the tests.
	@docker compose -f tests/integration/docker-compose.test.yml up --build --exit-code-from test-runner test-runner vuln-ssh; \
	EXIT_CODE=$$?; \
	# 4. Complete resource cleanup.
	docker compose -f tests/integration/docker-compose.test.yml down --volumes; \
	exit $$EXIT_CODE

test-unit:
	go test -v ./internal/...

test: test-unit test-integration