SHELL := /usr/bin/env bash

.PHONY: help test test-go test-js test-js-coverage build \
	go-fmt go-vet go-tidy go-check lint schema \
	validate-config print-schema render-config-example \
	proto-lint proto-breaking proto-generate e2e-docker

# Config/schema tooling: CONFIG_PATH=path BINARY=auth|proxy for validate-config;
# BINARY=auth|proxy and optional SCHEMA=path for print-schema;
# BINARY=auth|proxy FORMAT=json for render-config-example. (BINARY=agent is accepted as alias for auth.)
BINARY ?= auth
CONFIG_PATH ?=
SCHEMA ?=
FORMAT ?= json

# Proto tooling: use `buf` on PATH when present (e.g. CI buf-setup-action); else `go run` (no install).
ifeq ($(shell command -v buf 2>/dev/null),)
BUF := go run github.com/bufbuild/buf/cmd/buf@v1.50.0
else
BUF := buf
endif

help:
	@echo "Available targets:"
	@echo "  test                  Run all tests (Go + JS)"
	@echo "  test-go               Run Go tests"
	@echo "  test-js                Run JS SDK tests"
	@echo "  test-js-coverage       Run JS SDK tests with coverage"
	@echo "  build                  Build Go and JS packages"
	@echo "  go-fmt                 Run gofmt on Go files"
	@echo "  go-vet                 Run go vet on Go packages"
	@echo "  go-tidy                Run go mod tidy"
	@echo "  go-check               go-fmt + go-vet + test-go"
	@echo "  lint                   Run JS/TS linters (workspace)"
	@echo "  schema                 Generate JSON Schemas for configs (auth, proxy)"
	@echo "  validate-config        Validate config (need CONFIG_PATH=path [BINARY=auth|proxy])"
	@echo "  print-schema           Print schema to stdout (BINARY=auth|proxy or SCHEMA=path)"
	@echo "  render-config-example  Render example config from defaults (BINARY=auth|proxy FORMAT=json)"
	@echo "  proto-lint              Run buf lint on protobuf APIs"
	@echo "  proto-breaking          Run buf breaking checks against main"
	@echo "  proto-generate          Generate Go and TS code from protobufs (via buf)"
	@echo "  e2e-docker              Build+start the docker-compose quickstart stack, run the allow/deny smoke playbook, then down"

test: test-go test-js

# Avoid bash-only `mkdir -p` / GOTMPDIR so this target works when Make uses Windows cmd.
test-go:
	go test ./...

test-js:
	pnpm -r test

test-js-coverage:
	pnpm -r test:coverage

build:
	pnpm -r build

go-fmt:
	go fmt ./...

go-vet:
	go vet ./...

go-tidy:
	go mod tidy

go-check: go-fmt go-vet test-go

lint:
	pnpm -r lint

schema:
	go run ./cmd/schema

validate-config:
	@if [ -z "$(CONFIG_PATH)" ]; then \
		echo "validate-config: set CONFIG_PATH to a config file, e.g."; \
		echo "  make validate-config CONFIG_PATH=configs/auth.example.json BINARY=auth"; \
		echo "  make validate-config CONFIG_PATH=configs/proxy.example.json BINARY=proxy"; \
		exit 2; \
	fi
	CONFIG_PATH="$(CONFIG_PATH)" BINARY="$(BINARY)" go run ./cmd/validateconfig

print-schema:
	@b="$(BINARY)"; \
	if [ "$$b" = "agent" ]; then b=auth; fi; \
	if [ -n "$(SCHEMA)" ]; then cat "$(SCHEMA)"; else cat "schemas/$${b}.schema.json"; fi

render-config-example:
	BINARY="$(BINARY)" FORMAT="$(FORMAT)" go run ./cmd/renderconfig

proto-lint:
	$(BUF) lint

proto-breaking:
	$(BUF) breaking --against '.git#branch=main'

proto-generate:
	$(BUF) generate

# E2E: build + start the docker-compose quickstart stack, wait for the proxy to
# be healthy, run the allow/deny smoke playbook, then tear the stack down
# (teardown always runs, even if the playbook fails). The full lifecycle lives
# in test/e2e/run-docker-e2e.ps1 to avoid Make/cmd quoting pitfalls and to work
# on both Windows PowerShell 5.1 and PowerShell 7+. Uses Docker Compose v2
# (`docker compose`). Requires: docker (with the compose plugin).
# Seeds deployments/docker/.env from .env.example when missing.
e2e-docker:
	@powershell -NoProfile -ExecutionPolicy Bypass -File test/e2e/run-docker-e2e.ps1


