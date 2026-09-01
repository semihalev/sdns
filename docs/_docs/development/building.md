---
layout: doc
title: Building and testing
category: Development
order: 1
description: The build pipeline, the test suite, and the conventions a patch is expected to follow.
---

## Requirements

Go 1.24 or newer.

```bash
git clone https://github.com/semihalev/sdns
cd sdns
make all
```

`make all` runs generate, `go mod tidy`, the test suite and the build, in that
order. `go build` alone gives you just the binary.

## The Makefile targets

| Target | Does |
|---|---|
| `make all` | generate, tidy, test, build |
| `make test` | the full test suite |
| `go generate ./...` | regenerate generated files |
| `go build` | the binary only |

## Running one test

```bash
go test -v -race github.com/semihalev/sdns/middleware/cache -run TestName
```

`-race` is worth keeping on. The serving path is concurrent by design and a
race here is a correctness bug, not a flake.

## Before you send a patch

```bash
gofmt -w .
golangci-lint run
make test
```

CI runs the same linter configuration, so a clean local run is the same answer.

## Conventions

**No assertion libraries.** Tests use plain `testing` idioms — `if got != want
{ t.Errorf(...) }`. testify was removed from the repository deliberately; do
not reintroduce it or an equivalent.

**Name walking goes through `internal/dnsname`.** Do not call
`dns.UnpackDomainName`. The internal wire walkers (`AppendPresentation`,
`AppendFoldedKey`) do the same job without allocating, and the serving path
depends on that.

**Tests do not use the network.** A test that resolves a real name is not a
test of this code; it is a test of the machine it runs on. Stand up a loopback
authority instead.

**Every new behaviour gets a test.** Including the ones that are about what
does *not* happen — an allocation that must not occur, a code path that must
not be reachable. Those are the ones that silently regress.

## Regenerating the packaged configuration

The packaged `contrib/linux/sdns.conf` is produced from the config defaults, not
edited by hand:

```bash
SDNS_REGEN_CONFIG="$PWD/contrib/linux/sdns.conf" go test -run TestDumpDefaultConfig ./config/
```

The path must be absolute. Run it whenever you add or change a setting, or the
packaged file drifts from what the code actually accepts.

## Measurement

Performance claims need an A/B of real binaries, not a microbenchmark and an
argument. An optimisation that cannot be measured on the serving path is
reverted rather than kept on principle. The methodology and the published
numbers are in
[BENCHMARKS.md](https://github.com/semihalev/sdns/blob/main/BENCHMARKS.md).
