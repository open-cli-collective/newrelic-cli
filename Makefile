.PHONY: build clean test test-cover lint install release snapshot run fmt verify deps

BINARY_NAME=newrelic-cli
VERSION?=dev
COMMIT?=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE?=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS=-ldflags "-X github.com/piekstra/newrelic-cli/internal/version.Version=$(VERSION) \
	-X github.com/piekstra/newrelic-cli/internal/version.Commit=$(COMMIT) \
	-X github.com/piekstra/newrelic-cli/internal/version.BuildDate=$(BUILD_DATE)"

build:
	go build $(LDFLAGS) -o $(BINARY_NAME) ./cmd/newrelic-cli

clean:
	rm -f $(BINARY_NAME)
	rm -rf dist/

test:
	go test -race ./...

test-cover:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

test-short:
	go test -short ./...

lint:
	golangci-lint run

install: build
	mv $(BINARY_NAME) /usr/local/bin/

release:
	goreleaser release --clean

snapshot:
	goreleaser release --snapshot --clean

run: build
	./$(BINARY_NAME)

fmt:
	go fmt ./...

verify: fmt lint test
	@echo "All checks passed!"

deps:
	go mod tidy
	go mod download
