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
inside the cluster, or `~/.kube/config` when running outside it. Set it to a
path to use a specific kubeconfig.

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
dns_kubernetes_answered_total     queries it answered
dns_kubernetes_errors_total       API or lookup errors
dns_kubernetes_write_errors_total failures writing the response
```

`dns_kubernetes_errors_total` rising usually means the API connection has gone
away, an expired service account token, or RBAC that no longer permits the
watches.
