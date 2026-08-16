GO ?= go
BIN = sdns

all: generate tidy test build

.PHONY: test
test:
	# -coverpkg attributes cross-package execution: the wire serve paths
	# live in middleware/cache and internal/wire but are exercised from
	# the server package's integration tests, and without it their
	# coverage reads as zero.
	$(GO) test -v -race -covermode=atomic -coverpkg=./... -coverprofile=coverage.out ./...

.PHONY: generate
generate:
	$(GO) generate ./...

.PHONY: tidy
tidy:
	$(GO) mod tidy

.PHONY: build
build:
	$(GO) build

.PHONY: clean
clean:
	rm -f $(BIN)
	rm -f coverage.out
