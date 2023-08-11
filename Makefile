GO ?= go
TESTFOLDER := $(shell $(GO) list ./...)
BIN = sdns

all: generate tidy test build

.PHONY: test
test:
	echo "mode: atomic" > coverage.out
	for d in $(TESTFOLDER); do \
		$(GO) test -v -covermode=atomic -race -coverprofile=profile.out $$d > profiles.out; \
		cat profiles.out; \
		if grep -q "^--- FAIL" profiles.out; then \
			rm -rf profiles.out; \
			rm -rf profile.out; \
			exit 1; \
		fi; \
		if [ -f profile.out ]; then \
			cat profile.out | grep -v "mode:" >> coverage.out; \
			rm -rf profile.out; \
		fi; \
		rm -rf profiles.out; \
	done

.PHONY: generate
generate:
	$(GO) generate

.PHONY: tidy
tidy:
	$(GO) mod tidy

.PHONY: build
build:
	$(GO) build

.PHONY: clean
clean:
	rm -rf $(BIN)
	rm -rf zregister.go
