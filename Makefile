.PHONY: build test race cover lint fmt vet vuln clean corpus

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/omni-line/omni-audit/internal/version.Version=$(VERSION)

build:
	@mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/omni-audit ./cmd/omni-audit

test:
	go test ./...

race:
	go test -race -count=1 ./...

# Minimum statement coverage enforced locally and in CI.
COVER_MIN ?= 80

cover:
	go test -coverprofile=coverage.out ./...
	@total=$$(go tool cover -func=coverage.out | tail -1 | awk '{print $$NF}' | tr -d '%'); \
	echo "total: $${total}% (minimum $(COVER_MIN)%)"; \
	awk -v t="$$total" -v m="$(COVER_MIN)" 'BEGIN { if ((t+0) < (m+0)) { printf "coverage %.1f%% is below %s%%\n", t, m; exit 1 } }'

vet:
	go vet ./...

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')

lint:
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not installed; running go vet only"; go vet ./...; exit 0; }
	golangci-lint run ./...

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

corpus:
	go run ./scripts/update-corpus -out internal/corpus

clean:
	rm -rf bin dist coverage.out
