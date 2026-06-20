SHELL := /bin/sh

GOBIN := $(shell go env GOPATH)/bin

GOIMPORTS := $(GOBIN)/goimports
GOLANGCI_LINT := $(GOBIN)/golangci-lint

GOLANGCI_LINT_VERSION := v2.12.2

.PHONY: fmtcheck lint tools

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
