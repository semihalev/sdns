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
cache**, which is where a plugin can still see every query — including ones the
cache would otherwise answer.

## Configuring

```toml
[plugins]
    [plugins.example]
    path   = "/usr/lib/sdns/exampleplugin.so"
    config = {key_1 = "value_1", key_2 = 2, key_3 = true}
```

Load order follows the order of the blocks, and the `config` table is passed
through to the plugin.

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
go build -buildmode=plugin -o exampleplugin.so
```

## What loading enforces

Three things are checked, and each failure is logged and skipped rather than
fatal — one bad plugin does not stop the server:

- the file opens as a Go plugin;
- it exports `New`;
- `New` has exactly the signature above.

## The constraint worth knowing before you start

Go plugins require the plugin and the host to be built with the **same Go
version and the same dependency versions**. In practice that means rebuilding
your plugin whenever you upgrade sdns, and it means the plugin cannot be
distributed as a binary independent of the sdns build it targets.

If that is too brittle for your deployment, the alternative is to add the
middleware to the tree and build sdns with it —
[Middleware]({{ '/docs/development/middleware/' | relative_url }}) describes the
same interface, without the loading constraints.
