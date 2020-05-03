# SDNS HTTP API

You can manage all blocks with basic HTTP API functions.

## Authentication

WARNING: Currently, there is no authentication mechanism for API functions.

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
