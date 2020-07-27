GO ?= go
TESTFOLDER := $(shell $(GO) list ./...)
BIN = sdns

all: generate test build tidy

.PHONY: test
test:
	echo "mode: atomic" > coverage.out
	for d in $(TESTFOLDER); do \
		$(GO) test -v -covermode=atomic -race -coverprofile=profile.out $$d > tests.out; \
		cat tests.out; \
		if grep -q "^--- FAIL" tests.out; then \
			rm -rf tests.out; \
			rm -rf profile.out; \
			exit 1; \
		fi; \
		if [ -f profile.out ]; then \
			cat profile.out | grep -v "mode:" >> coverage.out; \
			rm -rf profile.out; \
		fi; \
		rm -rf tests.out; \
	done

.PHONY: generate
generate:
	$(GO) generate

.PHONY: build
build:
	$(GO) build

.PHONY: tidy
tidy:
	$(GO) mod tidy

.PHONY: clean
clean:
	rm -rf $(BIN)
	rm -rf generated.go
