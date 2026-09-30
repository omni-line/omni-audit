.PHONY: build test lint fmt vet clean

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X github.com/omni-line/omni-audit/internal/version.Version=$(VERSION)

build:
	@mkdir -p bin
	go build -ldflags "$(LDFLAGS)" -o bin/omni-audit ./cmd/omni-audit

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')

lint:
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not installed; running go vet only"; go vet ./...; exit 0; }
	golangci-lint run ./...

clean:
	rm -rf bin dist
