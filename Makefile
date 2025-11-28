GO ?= go
BIN = sdns

all: generate tidy test build

.PHONY: test
test:
	$(GO) test -v -race -covermode=atomic -coverprofile=coverage.out ./...

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
