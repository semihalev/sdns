#!/bin/sh

go get -v github.com/mitchellh/gox
${HOME}/go/bin/gox -osarch="linux/amd64 linux/arm linux/arm64 openbsd/amd64 netbsd/amd64 darwin/amd64 freebsd/amd64 windows/amd64" -output="sdns_{{.OS}}_{{.Arch}}" -ldflags="-s -w"
