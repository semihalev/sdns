---
layout: doc
title: Plugins
category: Development
order: 3
description: Loading a middleware from a shared object without forking the server.
---

A plugin is a Go plugin (`.so`) exporting a single symbol:

```go
func New(cfg *config.Config) middleware.Handler
```

It is loaded at startup and inserted into the chain immediately **before the
cache**, so a plugin sees queries the cache would otherwise have answered. It
does not see every query: access control, rate limiting, reflex, edns, chaos,
DDR, the hosts file, views, the blocklist, RPZ, AS112, kubernetes and DNS64 all
run earlier, and any of them can end the chain first.

The official release binaries and the Docker image **cannot load plugins**.
Releases are built with `CGO_ENABLED=0`, and Go's `plugin` package needs cgo;
without it every load fails with `plugin: not implemented`. The Docker image is
linked statically, so it cannot open a shared object either. To use plugins,
build sdns yourself with cgo enabled and dynamic linking, on linux, darwin or
freebsd (the only platforms the `plugin` package supports).

## Configuring

```toml
[plugins]
    [plugins.example]
    path   = "/usr/lib/sdns/exampleplugin.so"
    config = {key_1 = "value_1", key_2 = 2, key_3 = true}
```

`New` receives the whole `*config.Config`, not just its own table. A plugin
reads its settings from `cfg.Plugins["<block name>"].Config`, here
`cfg.Plugins["example"].Config`.

The block name (`example` above) becomes the plugin's registered middleware
name, and `Name()` must return the same string, otherwise the pipeline cannot
resolve the handler back by name.

Load order does **not** follow the order of the blocks. Plugins are held in a
map and registered by iterating it, so with more than one plugin their relative
order is undefined and can differ between restarts. Do not build behaviour that
depends on one plugin running before another.

A working example lives at
[semihalev/sdnsexampleplugin](https://github.com/semihalev/sdnsexampleplugin).

## Writing one

```go
package main

import (
    "context"

    "github.com/semihalev/sdns/config"
    "github.com/semihalev/sdns/middleware"
)

type example struct{}

func New(cfg *config.Config) middleware.Handler { return &example{} }

func (e *example) Name() string { return "example" }

func (e *example) ServeDNS(ctx context.Context, ch *middleware.Chain) {
    // inspect ch.Request, then continue the chain
    ch.Next(ctx)
}
```

```bash
# the plugin
CGO_ENABLED=1 go build -buildmode=plugin -o exampleplugin.so

# the host, from the sdns tree, same Go version and flags
CGO_ENABLED=1 go build -o sdns
```

## What loading enforces

Three things are checked, and each failure is logged and skipped rather than
fatal, one bad plugin does not stop the server:

- the file opens as a Go plugin;
- it exports `New`;
- `New` has exactly the signature above.

One failure is fatal: a block name equal to a name already in the chain (for
example `[plugins.cache]`, or `[plugins.blocklist]`) panics at startup with
`middleware: "<name>" already registered`. Pick a name no built-in middleware
uses.

## The constraint worth knowing before you start

Go plugins require the plugin and the host to be built with the **same Go
version, the same dependency versions and the same build flags**. If you build
sdns with `-trimpath`, as the release does, build the plugin with `-trimpath`
too. In practice that means rebuilding
your plugin whenever you upgrade sdns, and it means the plugin cannot be
distributed as a binary independent of the sdns build it targets.

If that is too brittle for your deployment, the alternative is to add the
middleware to the tree and build sdns with it,
[Middleware]({{ '/docs/development/middleware/' | relative_url }}) describes the
same interface, without the loading constraints.
