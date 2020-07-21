GO ?= go
GOFMT ?= gofmt "-s"
PACKAGES ?= $(shell $(GO) list ./... | grep -v /vendor/)
VETPACKAGES ?= $(shell $(GO) list ./... | grep -v /vendor/ | grep -v /examples/)
GOFILES := $(shell find . -name "*.go" -type f -not -path "./vendor/*")
TESTFOLDER := $(shell $(GO) list ./...)
APP_NAME=sdns

all: generate test build

.PHONY: test
test:
	echo "mode: atomic" > coverage.out
	for d in $(TESTFOLDER); do \
		$(GO) test -v -covermode=atomic -race -coverprofile=profile.out $$d; \
		if [ -f profile.out ]; then \
			cat profile.out | grep -v "mode:" >> coverage.out; \
			rm profile.out; \
		fi; \
	done

generate:
	$(GO) generate

build:
	$(GO) get -v github.com/mitchellh/gox
	${HOME}/go/bin/gox -osarch="linux/amd64 linux/arm linux/arm64 openbsd/amd64 netbsd/amd64 darwin/amd64 freebsd/amd64 windows/amd64" -output="${APP_NAME}_{{.OS}}_{{.Arch}}" -ldflags="-s -w"
	$(GO) mod tidy