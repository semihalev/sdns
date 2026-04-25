# HTTP API

You can manage all blocks with basic HTTP API functions.

All blocklist mutations (single and bulk) take effect immediately
and persist asynchronously: the in-memory state is updated under a
short-held lock, and the on-disk `local` blocklist file is rewritten
outside the lock via a temp-file + atomic rename. DNS queries are
not paused while a write lands, even during a multi-thousand-entry
bulk import.

## Authentication

API bearer token can be set on sdns config. If the token set, Authorization header should be send on API requests.
### Example Header
`Authorization: Bearer my_very_long_token`

## Actions

### GET /api/v1/block/set/:key

It is used to create a new block.

__request__

> curl http://localhost:8080/api/v1/block/set/domain.com

__response__

```json
{"success":true}
```

### GET /api/v1/block/get/:key

Used to request an existing block

__request__

> curl http://localhost:8080/api/v1/block/get/domain.com

__response__

```json
{"success":true}
```
or

```json
{"error":"domain.com not found"}
```

### GET /api/v1/block/exists/:key

It queries whether it has a block.

__request__

> curl http://localhost:8080/api/v1/block/exists/domain.com

__response__

```json
{"success":true}
```

### GET /api/v1/block/remove/:key

Deletes the block.

__request__

> curl http://localhost:8080/api/v1/block/remove/domain.com

__response__

```json
{"success":true}
```

### POST /api/v1/block/set/batch

Bulk-add multiple block entries in a single call. The whole batch
is applied as one map mutation and one disk write, so DNS queries
are not paused while a large import lands. Wildcard entries are
written as `*.example.com` (canonical FQDN), exactly like the
single-key form.

The request body is JSON, capped at 8 MiB. Unknown fields are
rejected. Whitelisted keys count toward `skipped`, not `added`.

__request__

> curl -X POST http://localhost:8080/api/v1/block/set/batch \
>      -H 'Content-Type: application/json' \
>      -d '{"keys":["domain.com","*.evil.example","tracker.test"]}'

__response__

```json
{"requested":3,"added":3,"skipped":0}
```

### POST /api/v1/block/remove/batch

Bulk-remove multiple block entries in a single call. Same one-lock
/ one-write semantics as the set batch above. Entries that aren't
present count toward `missing`, not `removed`.

__request__

> curl -X POST http://localhost:8080/api/v1/block/remove/batch \
>      -H 'Content-Type: application/json' \
>      -d '{"keys":["domain.com","*.evil.example","never-existed.test"]}'

__response__

```json
{"requested":3,"removed":2,"missing":1}
```

### GET /api/v1/purge/domain/type

Purge a cached query.

__request__

> curl http://localhost:8080/api/v1/purge/example.com/MX

__response__

```json
{"success":true}
```

### GET /metrics

Export the prometheus metrics.
