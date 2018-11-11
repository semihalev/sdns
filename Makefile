GO ?= go
GOFMT ?= gofmt "-s"
PACKAGES ?= $(shell $(GO) list ./... | grep -v /vendor/)
VETPACKAGES ?= $(shell $(GO) list ./... | grep -v /vendor/ | grep -v /examples/)
GOFILES := $(shell find . -name "*.go" -type f -not -path "./vendor/*")
TESTFOLDER := $(shell $(GO) list ./... | grep -E 'config$$|resolver$$|sdns$$|cache$$|doh$$|blocklist$$|hostsfile$$|accesslist$$|api$$|dnsutil$$|metrics$$')
APP_NAME=sdns

all: install

install: test

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

build:
	docker build -t $(APP_NAME) .
run:
	docker run -d --name sdns -p 53:53 -p 53:53/udp -p 853/tcp -p 8080/tcp sdns
