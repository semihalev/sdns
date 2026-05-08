# HTTP API

SDNS exposes an optional HTTP API for managing the blocklist, purging cached answers, scraping Prometheus metrics, and — with `SDNS_PPROF=1` — serving Go pprof profiles. It listens on whatever address you put in `api` in `sdns.conf` (default `127.0.0.1:8080`); set `api = ""` to turn it off entirely.

## Authentication

Set `bearertoken` in `sdns.conf` to require this header on every request:

```
Authorization: Bearer <token>
```

Missing, malformed, or mismatched headers get `401 {"error":"unauthorized"}`. The token is never logged.

`/debug/pprof/*` is the one exception — pprof tooling doesn't send `Authorization` headers, so those routes stay open even when a token is set. If you enable pprof, keep the API listener on loopback or behind an authenticating proxy.

## Endpoints

| Method | Path                          | Purpose                              |
| ------ | ----------------------------- | ------------------------------------ |
| GET    | `/api/v1/block/set/:key`      | Add a single block entry             |
| GET    | `/api/v1/block/get/:key`      | Look up a block entry                |
| GET    | `/api/v1/block/exists/:key`   | Membership probe                     |
| GET    | `/api/v1/block/remove/:key`   | Delete a block entry                 |
| POST   | `/api/v1/block/set/batch`     | Bulk-add (JSON body)                 |
| POST   | `/api/v1/block/remove/batch`  | Bulk-remove (JSON body)              |
| GET    | `/api/v1/purge/:qname/:qtype` | Drop cached answer for one question  |
| GET    | `/metrics`                    | Prometheus exposition                |
| GET    | `/debug/pprof/*`              | pprof (only with `SDNS_PPROF=1`)     |

The `block/*` routes are only registered when the blocklist middleware is enabled — without it they return `404`.

## Blocklist

`:key` is a domain name (`domain.com`) or wildcard (`*.evil.example`). Wildcards are canonicalised to `*.example.com.` form on disk, same as a manual entry in the local blocklist file.

```sh
$ curl http://localhost:8080/api/v1/block/set/domain.com
{"success":true}

$ curl http://localhost:8080/api/v1/block/exists/domain.com
{"exists":true}

$ curl -i http://localhost:8080/api/v1/block/get/missing.example
HTTP/1.1 404 Not Found
{"error":"missing.example not found"}

$ curl http://localhost:8080/api/v1/block/remove/domain.com
{"success":true}
```

`set` returns `success:false` when the key was already present or sits on the whitelist; `remove` returns `success:false` when the key wasn't there to begin with. `exists` is the only single-key endpoint that uses an `exists:` payload — the rest all return `success:`.

### Bulk operations

Both batch endpoints take the same body shape:

```json
{"keys": ["domain.com", "*.evil.example", "tracker.test"]}
```

The body is capped at 8 MiB and unknown fields are rejected. The whole batch lands as a single map mutation and a single disk write, so DNS queries aren't paused while a multi-thousand-entry import is running.

```sh
$ curl -X POST http://localhost:8080/api/v1/block/set/batch \
       -H 'Content-Type: application/json' \
       -d '{"keys":["domain.com","*.evil.example","tracker.test"]}'
{"requested":3,"added":3,"skipped":0}

$ curl -X POST http://localhost:8080/api/v1/block/remove/batch \
       -H 'Content-Type: application/json' \
       -d '{"keys":["domain.com","never-existed.test"]}'
{"requested":2,"removed":1,"missing":1}
```

`added` excludes duplicates and whitelisted keys; `removed` excludes keys that weren't present. So `requested = added + skipped` and `requested = removed + missing`.

A `200` response means in-memory state changed. The on-disk blocklist file is rewritten asynchronously via temp-file + atomic rename, so a crash or restart never sees a half-written file. Bad bodies (decoder error, unknown field, oversized payload) come back as `400` with the decoder's message; an empty or missing `keys` field returns `400 {"error":"keys is required and must be non-empty"}`.

## Cache purge

```sh
$ curl http://localhost:8080/api/v1/purge/example.com/MX
{"success":true}
```

The handler walks every middleware that exposes a `Purger` and drops cached entries for that question. Today that's the cache middleware (positive + negative entries for both `CD=0` and `CD=1`) and the resolver's nameserver cache (only for `qtype=NS`). `:qtype` is case-insensitive; unknown types are rejected before any cache is touched:

```sh
$ curl -i http://localhost:8080/api/v1/purge/example.com/FOO
HTTP/1.1 400 Bad Request
{"error":"unknown qtype: FOO"}
```

## Metrics

`GET /metrics` returns the Prometheus exposition for every metric the running middlewares register via `promauto` — cache, reflex, dns64, plugins, the lot. Auth-gated like everything else when a token is set.

## pprof

`SDNS_PPROF=1` in the sdns environment enables the standard `net/http/pprof` routes under `/debug/pprof/` (heap, goroutine, allocs, profile, symbol, trace). These bypass the bearer-token check; see Authentication.

## Server limits

`ReadHeaderTimeout` is 10 s. Batch bodies are bounded by `MaxBytesReader` at 8 MiB. Graceful shutdown waits up to 10 s for in-flight requests when the parent context is cancelled.
