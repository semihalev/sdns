---
layout: doc
title: Kubernetes
category: Features
order: 8
description: Serving cluster DNS (services, pods, SRV and PTR) from the Kubernetes API.
---

```toml
[kubernetes]
enabled        = true
cluster_domain = "cluster.local"
# kubeconfig   = ""

[kubernetes.ttl]
service = 30
pod     = 30
srv     = 30
ptr     = 30
```

Answers cluster DNS for services and pods directly from the Kubernetes API, so
one resolver serves both cluster names and the public namespace.

Off by default.

## Connecting to the API

Leave `kubeconfig` empty to use the in-cluster service account when running
inside the cluster. Outside it, `$KUBECONFIG` is used when set (a
colon-separated list is merged), and `~/.kube/config` otherwise. Set
`kubeconfig` to a path to use a specific file; an explicit path wins over the
in-cluster service account.

sdns connects once, at startup. If that first connection fails (no usable
config, or the API does not answer), it logs `Failed to connect to Kubernetes
API` and does not retry: names under `cluster_domain` get SERVFAIL until sdns
is restarted. Reverse lookups still fall through to normal resolution.

## Names served

Under `cluster_domain` (default `cluster.local`):

- Service A/AAAA records
- Pod A/AAAA records
- SRV records for named service ports
- PTR records for reverse lookups of cluster addresses

Anything outside `cluster_domain` falls through to normal resolution, which is
what makes running this alongside recursive resolution useful rather than
requiring a second resolver behind it.

## TTLs

The `[kubernetes.ttl]` block sets per-record-type TTLs in seconds, all 30 by
default. Cluster records change when the cluster changes, so these are short on
purpose; raise them only if you know your workloads are stable and you want to
cut lookup volume.

## Watching it

```
dns_kubernetes_queries_total      queries entering the middleware
dns_kubernetes_answered_total     queries it answered, SERVFAIL included
dns_kubernetes_errors_total       failures writing the response
dns_kubernetes_write_errors_total failures writing the response
```

Both error counters count only failed writes to the client; they move
together. They do not see the API. Until the informers have synced, and for
the whole run when the startup connection failed, names under `cluster_domain`
get SERVFAIL, and those replies count as answered. To tell whether the API side
is healthy, read the log: `Kubernetes DNS middleware initialized` reports
`k8s_connected`, `Kubernetes caches synced` marks the first full sync, and
`Failed to connect to Kubernetes API` or `Kubernetes client stopped with error`
mark failures.
