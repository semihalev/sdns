# Kubernetes DNS Middleware for SDNS

Kubernetes DNS middleware for SDNS. Resolves cluster-domain names
(services, pods, SRV, PTR) directly from a sharded in-memory registry
populated by Kubernetes informers. Each affected name's `dns.RR`
slices are pre-built on every mutation, so `ResolveQuery` is a single
sharded map lookup with zero allocations.

This middleware does **not** cache DNS responses, and the chain order
in `gen.go` places `kubernetes` before the `cache` middleware so the
cache layer doesn't see these answers either. That is by design:
registry lookups are already O(1), and only the `dns.Msg` setup +
wire packing in `ServeDNS` cost allocations on the hot path. If you
are debugging stale answers, the source of truth is the registry,
the upstream `cache` is not involved.

## Features

### DNS resolution

1. **Service DNS**
   - `service.namespace.svc.cluster.local` → ClusterIP
   - Headless services return all ready endpoint IPs
   - ExternalName services return CNAME records
   - Full IPv4 / IPv6 / dual-stack

2. **Pod DNS**
   - `pod-ip.namespace.pod.cluster.local` → Pod IP
   - IPv4: `10-244-1-1.namespace.pod.cluster.local`
   - IPv6: `2001-db8--1.namespace.pod.cluster.local`
   - StatefulSet pods: `pod-name.service.namespace.svc.cluster.local`

3. **SRV records**
   - `_port._protocol.service.namespace.svc.cluster.local`
   - TCP / UDP / SCTP

4. **PTR records (reverse DNS)**
   - IPv4: `1.0.96.10.in-addr.arpa` → service / pod
   - IPv6: `…ip6.arpa` → service / pod
   - O(1) reverse-IP index for services

5. **Kubernetes API integration**
   - Watches Services, EndpointSlices, and Pods
   - In-cluster config or external kubeconfig
   - Demo data fallback for local testing

### Registry

The registry is 256-way sharded:

- `serviceShards` keyed by `namespace/name`
- `podShards` keyed by IP
- `endpointShards` keyed by `namespace/service`
- `podByName` keyed by `namespace/name` (StatefulSet lookups, public accessor)
- `serviceByIP` keyed by ClusterIP string (PTR fast path)

Reads and writes against different shards never contend. Per-shard
RWMutexes serialise reads against any concurrent write to the same shard.

## File structure

- `kubernetes.go`: middleware entry, `New`, `ServeDNS`, `Stats`, demo seed
- `registry.go`: sharded `Registry`, query resolution + accessors
- `client.go`: Kubernetes API client (informers for Services, EndpointSlices, Pods)
- `types.go`: `Service`, `Pod`, `Endpoint`, `Port`
- `ipv6_utils.go`: IPv6 parsing helpers
- `constants.go`: TTLs, network octets, etc.
- `test_helpers.go`: mock `ResponseWriter` for tests

## Configuration

```toml
[kubernetes]
enabled = true
cluster_domain = "cluster.local"  # default

# kubeconfig = "/path/to/kubeconfig"  # optional, falls back to in-cluster
# demo = true                         # populate synthetic data for local testing

[kubernetes.ttl]
service = 30
pod     = 30
srv     = 30
ptr     = 30
```

> The legacy `killer_mode` flag is accepted for backward compatibility
> but has no effect, the middleware always uses the sharded registry.
> Remove it from your config; SDNS logs a deprecation warning if it is
> set to `true`.

## Query examples

```bash
# Service
dig @localhost service-name.namespace.svc.cluster.local

# Pod by IP
dig @localhost 10-244-1-1.namespace.pod.cluster.local

# SRV
dig @localhost _http._tcp.service-name.namespace.svc.cluster.local SRV

# Reverse
dig @localhost -x 10.96.0.1

# IPv6 service
dig @localhost service-name.namespace.svc.cluster.local AAAA
```

## Limitations

- Node DNS queries not implemented (rarely used in practice).
- Search domains must be configured in SDNS, not extracted from pods.
- EndpointSlices only, legacy Endpoints are not consumed.

## RBAC

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: sdns-kubernetes-dns
rules:
- apiGroups: [""]
  resources: ["services", "pods"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["discovery.k8s.io"]
  resources: ["endpointslices"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: sdns-kubernetes-dns
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: sdns-kubernetes-dns
subjects:
- kind: ServiceAccount
  name: sdns
  namespace: sdns-system
```

## Stats

`Kubernetes.Stats()` returns:

- `queries`, `answered`, `errors`, `write_errors`
- `registry`: per-registry counters (`services`, `pods`, `endpoints`,
  `endpoint_sets`, `queries`, `hits`, `hit_rate_pct`, `shards`)

## Troubleshooting

**No Kubernetes connection.** Verify kubeconfig path, in-cluster pod
identity, and RBAC permissions for Services / Pods / EndpointSlices.

**Queries not resolving.** Ensure `cluster_domain` matches the
cluster's actual domain (`kubectl get cm -n kube-system coredns -o yaml`
shows the answer if you're migrating from CoreDNS). Check that
informers have synced, the middleware passes through to the next
handler until at least one informer has populated the registry.

**Cache behaviour.** This middleware does not cache responses, and the
`cache` middleware sits *below* it in the chain (see `gen.go`) so it
never sees Kubernetes answers either. There is no DNS-message cache in
this path. Stale answers can therefore only come from stale informer
state, check `Stats()["registry"]` and the Kubernetes API directly,
not the cache middleware.
