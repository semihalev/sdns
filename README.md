<p align="center">
  <img src="https://github.com/semihalev/sdns/blob/main/logo.png?raw=true" width="200">
</p>

<h1 align="center">SDNS :rocket:</h1>

<p align="center">
  A high-performance, recursive DNS resolver server with DNSSEC support, focused on preserving privacy.
</p>

<p align="center">
  <a href="https://github.com/semihalev/sdns/actions"><img src="https://img.shields.io/github/actions/workflow/status/semihalev/sdns/ci.yml?style=flat-square"></a>
  <a href="https://goreportcard.com/report/github.com/semihalev/sdns"><img src="https://goreportcard.com/badge/github.com/semihalev/sdns?style=flat-square"></a>
  <a href="http://godoc.org/github.com/semihalev/sdns"><img src="https://img.shields.io/badge/godoc-reference-blue.svg?style=flat-square"></a>
  <a href="https://codecov.io/gh/semihalev/sdns"><img src="https://img.shields.io/codecov/c/github/semihalev/sdns?style=flat-square"></a>
  <a href="https://github.com/semihalev/sdns/releases"><img src="https://img.shields.io/github/v/release/semihalev/sdns?style=flat-square"></a>
  <a href="https://github.com/semihalev/sdns/blob/main/LICENSE"><img src="https://img.shields.io/github/license/semihalev/sdns?style=flat-square"></a>
</p>

***

## Installation

Install SDNS using the `go install` command:

```shell
go install github.com/semihalev/sdns@latest
```

#### Pre-built Binaries

Download the latest release from the [GitHub Releases](https://github.com/semihalev/sdns/releases/latest) page.

#### Docker

Multi-arch images (linux/amd64, linux/arm64) are published on every tagged release to both registries:

*   [GitHub Container Registry](https://github.com/semihalev/sdns/pkgs/container/sdns): `ghcr.io/semihalev/sdns`
*   [Docker Hub](https://hub.docker.com/r/c1982/sdns): `c1982/sdns`

```shell
$ docker run -d --name sdns -p 53:53 -p 53:53/udp ghcr.io/semihalev/sdns:latest
```

Pin to a specific version (recommended for production):

```shell
$ docker run -d --name sdns -p 53:53 -p 53:53/udp ghcr.io/semihalev/sdns:1.8.2
```

#### Docker Compose

Install `docker-compose` and run from the root directory:

```shell
$ sudo apt install docker-compose
$ docker-compose up -d
```

#### Homebrew for macOS

Install and run as a service:

```shell
$ brew install sdns
$ brew install semihalev/tap/sdns (updated every release)
$ brew services start sdns
```

#### Snapcraft

```shell
$ snap install sdns
```

#### AUR for ArchLinux

```shell
$ yay -S sdns-git
```

> **Note:** Pre-built binaries, Docker packages, brew taps, and snaps are automatically created by GitHub [workflows](https://github.com/semihalev/sdns/actions).

## Building from Source

```shell
$ go build
```

## Testing

```shell
$ make test
```

## Flags

| Flag              | Description                                                                    |
| ----------------- | ------------------------------------------------------------------------------ |
| -c, --config PATH | Location of the config file. If it doesn't exist, a new one is generated at that path. Default: sdns.conf (working directory) |
| -t, --test        | Test configuration file and exit. Returns exit code 0 if valid, 1 if invalid. Checks every setting it can judge — addresses, IPs, CIDRs, enumerated values, upstream formats, TLS files — and reports all problems at once. It also fails on keys the file carries that no setting claims: a typo, or a key an older SDNS understood. Startup only warns about those, so upgrading with a stale key does not become an outage |
| -h, --help        | Show help information and exit                                                 |

`sdns version` prints the SDNS version and the Go toolchain it was built with.

## Debugging Environment

To debug your environment, execute the following command:

```shell
$ export SDNS_DEBUGNS=true && export SDNS_PPROF=true && ./sdns
```

The `SDNS_DEBUGNS` environment variable is beneficial for verifying the RTT (Round Trip Time) of authoritative servers. To use it, send an HINFO query for zones with chaos class.

Here's an example of the output you might receive:

```shell
$ dig chaos hinfo example.com

; <<>> DiG 9.17.1 <<>> chaos hinfo example.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 29636
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 4, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
; COOKIE: f27dbb995df5ac79e4fa37c07d131b5bd03aa1c5f802047a7c02fb228a886cb281ecc319323dea81 (good)
;; QUESTION SECTION:
;example.com.			CH	HINFO

;; AUTHORITY SECTION:
example.com.		0	CH	HINFO	"Host" "IPv4:199.43.135.53:53 rtt:142ms health:[GOOD]"
example.com.		0	CH	HINFO	"Host" "IPv4:199.43.133.53:53 rtt:145ms health:[GOOD]"
example.com.		0	CH	HINFO	"Host" "IPv6:[2001:500:8f::53]:53 rtt:147ms health:[GOOD]"
example.com.		0	CH	HINFO	"Host" "IPv6:[2001:500:8d::53]:53 rtt:148ms health:[GOOD]"
```

## Configuration (v1.8.2)

Every setting lives in one TOML file (`sdns.conf`; a commented template is generated on first run). Simple keys are listed in the table below; the feature blocks each have their own section with examples:
[**[rpz]**](#response-policy-zones-rpz) ·
[**[recursion_firewall]**](#recursion-firewall) ·
[**[ecs]**](#edns-client-subnet-rfc-7871) ·
[**[dns64]**](#dns64-rfc-6147) ·
[**[kubernetes]**](#kubernetes-dns-middleware) ·
[**[[forward_zone]]**](#per-zone-forwarding) ·
[**[[views]]**](#views-per-client-static-answers) ·
[**[plugins]**](#external-plugins)

| Key                  | Description                                                                                                         |
| -------------------- | ------------------------------------------------------------------------------------------------------------------- |
| **version**          | Configuration file version                                                                                          |
| **directory**        | Working directory for SDNS data storage. Must be writable by the SDNS process. Default: "/db"                        |
| **bind**             | DNS server binding address and port. Default: ":53" (0.0.0.0:53 and [::]:53)                                                                 |
| **bindtls**          | DNS-over-TLS (DoT) server binding address. Default: ":853"                                                          |
| **binddoh**          | DNS-over-HTTPS (DoH) server binding address. Default: ":8053"                                                       |
| **binddoq**          | DNS-over-QUIC (DoQ) server binding address. Default: ":853"                                                         |
| **tlscertificate**   | Path to the TLS certificate file for DoT/DoH/DoQ. Automatically reloaded on changes                                 |
| **tlsprivatekey**    | Path to the TLS private key file for DoT/DoH/DoQ. Automatically reloaded on changes                                 |
| **outboundips**      | Outbound IPv4 addresses for DNS queries. Multiple addresses enable random source IP selection per request            |
| **outboundip6s**     | Outbound IPv6 addresses for DNS queries. Multiple addresses enable random source IP selection per request            |
| **rootservers**      | Root DNS servers (IPv4). These are the authoritative name servers for the DNS root zone                             |
| **root6servers**     | Root DNS servers (IPv6). These are the authoritative name servers for the DNS root zone                             |
| **dnssec**           | Enable DNSSEC validation for secure DNS responses. Options: "on" or "off". Default: "on"                            |
| **rfc8198**          | Aggressively reuse validated NSEC/NSEC3 proofs. Set false to stop RFC 8198 admission and synthesis without disabling DNSSEC, exact negative caching, or RFC 8020 cuts. Default: true |
| **rfc9520**          | Cache shared recursive-resolution and failed-authority state. Emergency rollback switch; setting false means SERVFAIL responses and failed-authority state are not cached, which can increase upstream retry load. Per-server retry ceilings, request work limits, and ordinary DNS caching remain active. Default: true |
| **serve_stale**      | Serve expired positive answers as a last resort after resolution ends in SERVFAIL (RFC 8767). A learned delegation lease remains a hard ceiling. Default: false |
| **serve_stale_max_ttl** | Maximum time an answer may be served after its TTL expires (duration string). An explicit `0s` leaves the delegation lease as the only upper bound; because forwarder mode learns no delegation cut, `0s` there permits retention until cache eviction. Default: `24h` |
| **[recursion_firewall]** | Request-tree work budgets (outbound/internal queries, DNSSEC operations) with off/shadow/enforce modes, plus RFC 9520 failure-cache tuning. See the Recursion Firewall section below |
| **[rpz]**            | Response Policy Zones: subscribe to policy feeds — local files or vendor AXFR, TSIG-signed if the provider requires it — that rewrite, deny, or drop answers by query name, client address, or answer address. `enabled`, `mode` ("shadow"/"enforce"), and one `[[rpz.zone]]` entry per zone. See [Response Policy Zones](#response-policy-zones-rpz) |
| **[ecs]**            | EDNS Client Subnet (RFC 7871): forward truncated client prefixes upstream and cache answers per scope. See [EDNS Client Subnet](#edns-client-subnet-rfc-7871) |
| **[dns64]**          | DNS64 synthesis for IPv6-only clients (RFC 6147) with per-network gating and exclusions. See [DNS64](#dns64-rfc-6147) |
| **[kubernetes]**     | Kubernetes DNS: serve `cluster.local` services, pods, SRV, and PTR straight from the API server. See [Kubernetes DNS Middleware](#kubernetes-dns-middleware) |
| **rootkeys**         | DNSSEC root zone trust anchors in DNSKEY format                                                                     |
| **fallbackservers**  | Upstream DNS servers used when all others fail. Format: "IP:port" (e.g., "8.8.8.8:53")                             |
| **[[forward_zone]]** | Per-zone forwarding: `name` plus `servers` sends that zone's queries to its own recursive upstreams while everything else resolves normally. Most specific zone wins. Servers accept the same formats as **forwarderservers**. A forwarded zone is not validated locally — see [Per-zone forwarding](#per-zone-forwarding) |
| **forwarderservers** | Forward all queries to these DNS servers. Accepts `IP:port` (plain UDP/TCP), `tls://IP:port` (DoT, RFC 7858), or `https://host/dns-query` (DoH, RFC 8484; hostname or IP literal). See [Forwarder upstreams](#forwarder-upstreams) for details. |
| **api**              | HTTP API server binding address for statistics and control. Leave empty to disable                                  |
| **bearertoken**      | API bearer token for authorization. If set, Authorization header must be included in API requests                   |
| **blocklists**       | URLs of remote blocklists to download and use for filtering                                                         |
| **blocklistdir**     | \[DEPRECATED] Blocklist directory. Now automatically created in the working directory                               |
| **loglevel**         | Logging verbosity level. Options: error, warn, info, debug. Default: "info"                                  |
| **accesslog**        | Path to the access log file in Common Log Format. Leave empty to disable                                            |
| **nullroute**        | IPv4 address returned for blocked A queries. Default: "0.0.0.0"                                                     |
| **nullroutev6**      | IPv6 address returned for blocked AAAA queries. Default: "::0"                                                      |
| **accesslist**       | IP addresses/subnets allowed to make queries. Default allows all: ["0.0.0.0/0", "::0/0"]                           |
| **querytimeout**     | Maximum time to wait for any DNS query to complete. Default: "10s"                                                  |
| **timeout**          | Network timeout for upstream DNS queries. Default: "2s"                                                             |
| **hostsfile**        | Path to hosts file (RFC 952/1123 format) for local resolution. Auto reloads with fs watch. (The directory of the file is being watched, not the file. Best practice is to deploy the file in an individual directory.) Leave empty to disable |
| **expire**           | Cache TTL for error responses in seconds. Default: 600                                                              |
| **cachesize**        | Maximum number of cached DNS records. Default: 256000                                                               |
| **prefetch**         | Prefetch threshold percentage (10-90). Refreshes popular cache entries before expiration. 0 disables               |
| **maxdepth**         | Maximum recursion depth for queries. Prevents infinite loops. Default: 30                                           |
| **ratelimit**        | Global query rate limit per second. 0 disables. Default: 0                                                          |
| **clientratelimit**  | Per-client rate limit per minute. 0 disables. Default: 0                                                            |
| **domainmetrics**    | Enable per-domain query metrics collection. Default: false                                                          |
| **domainmetricslimit** | Maximum number of domains to track in metrics. 0 = unlimited (use with caution). Default: 1000                  |
| **blocklist**        | Manual domain blocklist. Domains listed here will be blocked                                                        |
| **whitelist**        | Manual domain whitelist. Overrides blocklist matches                                                                |
| **cookiesecret**     | DNS cookie secret (RFC 7873) for client verification. Auto-generated if not set                                     |
| **nsid**             | DNS server identifier (RFC 5001) for identifying this instance. Leave empty to disable                              |
| **chaos**            | Enable responses to version.bind and hostname.bind chaos queries. Default: true                                     |
| **qname_max_minimize_count** | QNAME minimization (RFC 9156): minimized queries one lookup may spend before the full name goes out. 0 disables. Default: 10 |
| **qname_minimize_one_label** | How many of those queries add a single label before the rest are grouped. 0 selects the RFC's suggested 4. Default: 4 |
| **qname_min_level**  | Deprecated. Counted delegation depth instead of queries spent; still read when **qname_max_minimize_count** is unset |
| **hyperlocal_root**  | Serve the root zone from a local copy (RFC 8806): AXFR from the root servers, ZONEMD-verified (RFC 8976) against the trust anchors, refreshed on the zone's SOA schedule. Root referrals, junk-TLD NXDOMAINs and questions at the root itself (`. NS`, `. SOA`, `. DNSKEY`) cost no upstream query. Default: false |
| **hyperlocal_root_sources** | Transfer sources (host:port) for the local root copy. Empty selects the RFC 8806 appendix set |
| **emptyzones**       | Enable local authoritative responses for RFC 1918 zones. See http://as112.net/ for details                         |
| **tcpkeepalive**     | Enable TCP connection pooling for root and TLD servers. Improves performance by reusing connections. Default: false |
| **roottcptimeout**   | TCP idle timeout for root server connections. Default: "5s"                                                          |
| **tldtcptimeout**    | TCP idle timeout for TLD server connections (com, net, org, etc.). Default: "10s"                                   |
| **tcpmaxconnections**| Maximum number of pooled TCP connections. 0 uses default. Default: 100                                               |
| **maxconcurrentqueries** | Maximum number of concurrent DNS queries allowed. Limits resource usage under heavy load. Default: 10000         |
| **reflexenabled**    | Enable DNS amplification/reflection attack detection. Default: false                                                |
| **reflexblockmode**  | Block detected attacks (if false, only logs). Default: true                                                         |
| **reflexlearningmode** | Log detections without blocking for threshold tuning. Default: false                                              |
| **reflexthreshold**  | Suspicion score threshold (0.0-1.0). Lower = more aggressive. Default: 0.7                                          |
| **dnstapsocket**     | Unix domain socket path for dnstap binary DNS logging. Leave empty to disable                                       |
| **dnstapidentity**   | Server identity string for dnstap messages. Defaults to hostname                                                    |
| **dnstapversion**    | Server version string for dnstap messages. Default: "sdns"                                                          |
| **dnstaplogqueries** | Log DNS queries via dnstap. Default: true                                                                           |
| **dnstaplogresponses** | Log DNS responses via dnstap. Default: true                                                                        |
| **dnstapflushinterval** | Dnstap message flush interval in seconds. Default: 5                                                             |
| **views**            | Per-client static-answer rules. Each entry has `zone` (label), `networks` (CIDRs), and `answers` (zone-file RRs). See the Views middleware section below for shape and examples |
| **ingressworkers**   | Fixed handler workers per listener. Default: derived from this machine's CPUs and memory                            |
| **ingressqueue**     | Ready-queue depth before a query is served on its own goroutine. Default: 64                                        |
| **ingresstcpconns**  | Concurrent inbound TCP/DoT connection cap. Default: derived from this machine's memory and file-descriptor limit    |
| **memorytrim**       | Return a traffic burst's memory to the OS after a long idle. Off by default; meant for memory-constrained devices   |
| **ipv6access**       | Force IPv6 upstream access on. When unset, SDNS probes at startup and uses IPv6 authoritative servers only if the host actually has IPv6 transit — set true if the probe misjudges your network |
| **[plugins]**        | External plugin configuration, one `[plugins.name]` block per plugin with `path` and free-form `config` keys. Loaded before the cache middleware, in declaration order. See [External Plugins](#external-plugins) |

## Middleware Configuration

SDNS supports a flexible middleware architecture that allows extending its functionality through built-in middlewares and external plugins.

### Built-in Middlewares

#### Kubernetes DNS Middleware

The Kubernetes middleware provides full DNS integration for Kubernetes clusters, supporting all standard Kubernetes DNS patterns.

**Features:**
- Service DNS resolution (A, AAAA, CNAME, SRV)
- Pod DNS resolution (by IP and hostname)
- Headless services and StatefulSets
- ExternalName services
- Full IPv6 and dual-stack support
- Real-time Kubernetes API synchronization
- 256-way sharded registry for concurrent informer writes and lock-free reads
- Reverse-IP and pod-by-name indexes for O(1) PTR / StatefulSet lookups

**Configuration:**
```toml
[kubernetes]
enabled = true
cluster_domain = "cluster.local"  # Default: cluster.local
# kubeconfig = "/path/to/kubeconfig"  # Optional, uses in-cluster config by default

# Per-record-type TTLs (seconds) for the answers the middleware serves.
[kubernetes.ttl]
service = 30
pod = 30
srv = 30
ptr = 30
```

> The legacy `killer_mode` flag is accepted for backward compatibility
> but has no effect — the middleware always uses the sharded registry.
> A `demo` flag exists for development only: it fills the registry with
> synthetic services so the middleware answers without a cluster — never
> enable it in production.

For detailed information, see the [Kubernetes middleware documentation](middleware/kubernetes/README.md).

#### Reflex: DNS Amplification Attack Detection

The Reflex middleware detects and blocks DNS amplification/reflection attacks by analyzing IP behavior patterns.

**How It Works:**
- Tracks query patterns per source IP (rate, types, amplification ratio)
- Identifies spoofed IPs used in reflection attacks
- TCP connections prove real IP ownership (clears suspicion)
- Bounded memory usage with automatic cleanup

**Detection Factors:**
- High query rate from single IP
- High-amplification query types only (DNSKEY, TXT, etc.)
- Lack of normal queries (A, AAAA)
- Actual response/request amplification ratio
- Low query type diversity

**Configuration:**
```toml
reflexenabled = false       # Enable detection
reflexblockmode = true      # Block attacks (false = log only)
reflexlearningmode = false  # Log without blocking for tuning
# reflexthreshold = 0.7     # Score threshold (0.0-1.0)
```

**Prometheus Metrics:**
- `reflex_detections_total` - Suspected attacks by query type
- `reflex_blocked_total` - Blocked queries
- `reflex_tracked_ips` - Currently tracked IPs

#### Views: Per-Client Static Answers

The Views middleware serves different DNS answers based on the client's source IP — a split-horizon resolver where a name like `*.example.lan.` can resolve to one address for LAN clients and a different address for VPN clients, all without disturbing recursion for everyone else.

**How It Works:**
- Each view declares a list of CIDR `networks` and a list of zone-file `answers`.
- A query whose source IP falls in one of a view's networks is matched against that view's answers (by name and qtype, with `*.zone.` wildcard support per RFC 4592).
- A matching answer is synthesised with the query name as owner and short-circuits the chain.
- A query that matches the view's networks but has no matching answer (or comes from a client outside every view's networks) falls through to the rest of the chain — blocklist, cache, resolver, etc.
- Internal sub-queries skip the views middleware entirely (no real client IP).

**Configuration:**
```toml
[[views]]
zone = "lannet"
networks = ["192.168.1.0/24"]
answers = [
    "*.example.lan. 60 IN A 192.168.1.3",
    "*.example.lan. 60 IN AAAA fd00::3",
]

[[views]]
zone = "vpnnet"
networks = ["100.64.0.0/24"]
answers = [
    "*.example.lan. 60 IN A 100.64.0.2",
]
```

Views are evaluated in declaration order; the first whose `networks` contains the client IP wins. `zone` is a free-form label used in error logs — it doesn't have to be a DNS zone name.

#### Response Policy Zones (RPZ)

The RPZ middleware subscribes the resolver to policy zones — locally maintained files or vendor AXFR feeds in the standard RPZ encoding — that rewrite, deny, or drop answers for the names and client networks they list. Existing commercial feeds work unmodified.

**Configuration:**
```toml
[rpz]
enabled = true
mode = "shadow"    # "shadow" counts and logs every match without rewriting; "enforce" acts

# A file-fed zone: reloaded automatically when the file is replaced.
[[rpz.zone]]
name = "badlist"                       # label for metrics, logs and the EDE text
file = "/var/lib/sdns/badlist.zone"
policy = "given"                       # per-zone override, see below

# An AXFR-fed zone: follows the feed's own SOA schedule.
[[rpz.zone]]
name = "vendorfeed"
source = "203.0.113.5:53"              # the feed's primary (host:port)
origin = "rpz.vendor.example."         # the policy zone's apex
# tsig_key = "feedkey.:hmac-sha256.:BASE64SECRET"   # when the provider signs transfers
```

Each `[[rpz.zone]]` entry (a zone is fed exactly one way — `file` or `source`):

| Field        | Description |
| ------------ | ----------- |
| **name**     | Zone label used in metrics, logs, and the EDE text. Required, unique across zones |
| **file**     | Path to a local policy zone file. Reloaded automatically when the file is replaced — the file's directory is watched, so atomic renames are caught. Best practice: deploy the file in its own directory |
| **source**   | AXFR primary (`host:port`) of a vendor feed. The feed keeps itself current on the zone's own SOA schedule: probe on refresh, transfer on serial change, retry on retry, and withdraw past expire |
| **origin**   | The policy zone's apex as an FQDN. Required with `source`; refused with `file` (the file's own SOA names the apex) |
| **tsig_key** | `name:algorithm:base64-secret` for signed transfers. Algorithms: `hmac-sha1`, `hmac-sha224`, `hmac-sha256`, `hmac-sha384`, `hmac-sha512`. Only meaningful with `source` |
| **policy**   | Per-zone action override; default `given`. See the override list below |
| **cname**    | Walled-garden target FQDN; required exactly when `policy = "cname"` |

Zones are evaluated in the order written; the first zone with a match wins. Within a zone, a client-address (`rpz-client-ip`) match outranks a name match, which outranks an answer-address (`rpz-ip`) match; the longest prefix or most specific name wins. Answer-address policy is judged against what a query actually resolved to — the cache keeps storing the unmodified answer, only the client's response is rewritten, so per-client exemptions keep working across cached entries and a reload re-evaluates already-cached answers on their next hit.

**Triggers:** QNAME rules (exact and `*.wildcard`), CLIENT-IP rules, and IP (answer-address, `rpz-ip`) rules — the address triggers take IPv4 and IPv6 prefixes in the standard reversed-owner encoding. Triggers of other types in a feed (`rpz-nsdname`, `rpz-nsip`) load without error and are counted as skipped.

**Actions** (standard RPZ RDATA encodings): NXDOMAIN (`CNAME .`), NODATA (`CNAME *.`), PASSTHRU, DROP (no answer at all), TCP-Only (truncates UDP; encrypted transports pass), and Local Data — served as if authoritative for the query name, including CNAME chasing through the resolver.

**Per-zone `policy` override:** `given` uses what each rule says; `passthru`, `nxdomain`, `nodata`, `drop`, `tcp-only` replace every action in the zone; `cname` rewrites every match to the `cname = "target."` walled garden; `disabled` only observes — a later zone still acts.

**Operational behavior:**
- Policy applies to client queries only (RD=1); the resolver's own internal lookups are never policy-checked.
- Rewritten answers carry the policy zone's SOA in the additional section and Extended DNS Error 17 (Filtered), and never claim DNSSEC authenticity.
- A file push that fails to parse — or parses but contains no rules — keeps the previous rules serving and is counted, never silently unprotected.
- An AXFR feed probes the SOA on its refresh interval, transfers on serial change, refuses serial rollbacks (RFC 1982), and **withdraws its rules past SOA expire** — a feed that cannot be refreshed fails open rather than enforcing stale policy.
- `sdns -t` validates the whole `[rpz]` block, parsing file-fed zones with the same loader the server uses.
- A non-matching query costs zero heap allocations; a 2M-rule feed measured no serving-path regression.

**Metrics:** `rpz_action_total{zone,trigger,action,outcome}` (`outcome="enforced"` for the acting match, `"observed"` for shadow mode and disabled zones), `rpz_zone_rules{zone,trigger}`, `rpz_zone_rules_skipped{zone,reason}`, `rpz_reload_errors_total{zone}`, `rpz_zone_serial{zone}` (-1 for file-fed or withdrawn zones).

#### DNS64 (RFC 6147)

The DNS64 middleware lets IPv6-only clients reach IPv4-only services. When a client AAAA query has no usable answer, the middleware issues a secondary A-record lookup and synthesises AAAA records by embedding each IPv4 address into a configured Pref64::/n IPv6 prefix (RFC 6052). The client receives addresses in a NAT64-routable subnet and can connect to the IPv4-only target through a paired NAT64 gateway.

**How It Works:**

- The middleware sits between the `kubernetes` and `cache` middlewares. The cache stores the original AAAA response — synthesis runs per client query against that cached response. The secondary A lookup itself is cached, so repeat synthesis is bounded to a memcpy plus a cache hit. This preserves per-client correctness when `client_networks` restricts who gets synthesis.
- **RCODE handling** follows RFC 6147 §5.1.2 / §5.1.3 / §5.5:
  - `NOERROR` with at least one usable AAAA → pass through (after AAAA exclusion filtering, see below).
  - `NXDOMAIN` → pass through unchanged. The name doesn't exist, so it has no A either.
  - `SERVFAIL` carrying a DNSSEC-failure Extended DNS Error (codes 1/2/5–12/27 — Unsupported DNSKEY Algorithm, Unsupported DS Digest Type, DNSSEC Indeterminate, DNSSEC Bogus, Signature Expired/Not Yet Valid, DNSKEY/RRSIGs/NSEC Missing, No Zone Key Bit Set, Unsupported NSEC3 Iterations Value) → pass through unchanged. Synthesising over a validation failure would let an attacker bypass DNSSEC.
  - `NOERROR` with no usable AAAA, or any other nonzero RCODE (`SERVFAIL` without a DNSSEC EDE, `REFUSED`, etc.) → treated as "no answer" and the secondary A lookup is attempted. When the A query yields empty/error too, that response (rcode + Authority + any CNAME/DNAME chain) becomes the basis for the client reply per §5.1.6.
- **Recursion bit:** `RD=0` queries skip DNS64 entirely. Synthesis requires a recursive secondary lookup, so honouring the client's non-recursive intent means stepping aside.
- **AAAA exclusion (RFC 6147 §5.1.4):** AAAA records returned by the upstream are filtered against `exclude_aaaa_networks` (default `::ffff:0:0/96` IPv4-mapped) before deciding pass-through vs synthesis. If every AAAA is excluded, the response is treated as if no AAAA were returned and synthesis proceeds. Excluded AAAAs are stripped from the Answer section even on the pass-through path so they never reach the client.
- **A side filtering (RFC 6147 §5.1.4):** when the active prefix is the IANA Well-Known `64:ff9b::/96`, IPv4 addresses inside `exclude_a_networks` are dropped from synthesis. Operator-chosen prefixes ignore that list — you picked the prefix knowing the network's reachability.
- **CNAME / DNAME chains (RFC 6147 §5.1.5)** are carried through into the synthesised answer. Synthesised AAAAs adopt the A record's owner — the terminal name after the chain has resolved.
- **TTL (RFC 6147 §5.1.7):** the synthesised AAAA TTL is `min(A record TTL, AAAA negative-cache TTL)`. When the original AAAA carried no SOA, the synth TTL caps at 600 s. No artificial floor.
- **Multi-prefix synthesis (RFC 6147 §5.2):** every configured prefix produces its own synthesised AAAA per A record, so a client receives every reachable Pref64 path in a single response. Per-prefix RFC 6147 §5.1.4 filtering still applies — a private IPv4 may be excluded under `64:ff9b::/96` but synthesised under an operator prefix listed alongside it.
- **PTR translation (RFC 6147 §5.3.1):** `ip6.arpa` PTR queries whose embedded IPv4 falls under any configured Pref64 are answered with a CNAME pointing at the corresponding `in-addr.arpa` name; if the chase succeeds, the resolved PTR records are appended. Names that decode to addresses outside every Pref64 (or whose IPv4 hits the §5.1.4 exclusion under the well-known prefix) flow through normal recursion so real reverse zones still answer.
- **DNSSEC (RFC 6147 §5.5):** when the original NODATA was `AD=1`, the synthesised reply clears AD and attaches Extended DNS Error 4 ("Forged Answer"). Clients that set `CD=1` are validating themselves and bypass synthesis (both AAAA and PTR paths).
- **Internal sub-queries** (resolver NS chase, cache CNAME chase) skip DNS64 entirely — synthesis is a client-facing concern, not part of resolution semantics.

**Configuration:**
```toml
[dns64]
enabled = true
prefixes = ["64:ff9b::/96"]         # IANA Well-Known Prefix; or your own /32, /40, /48, /56, /64, /96. List multiple to synthesise one AAAA per prefix per A.
client_networks = []                # Empty = all clients eligible; restrict to your IPv6-only subnets to scope synthesis
exclude_zones = []                  # FQDNs (suffix match) whose AAAA must never be synthesised
exclude_aaaa_networks = ["::ffff:0:0/96"]  # IPv6 prefixes whose AAAA records are filtered out of upstream replies (RFC 6147 §5.1.4)
exclude_a_networks = [              # IPv4 ranges skipped under the well-known prefix only (RFC 6147 §5.1.4)
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    # …plus the rest of the IANA Special-Purpose Address Registry; defaults documented in sdns.conf
]
```

`exclude_aaaa_networks` defaults to `["::ffff:0:0/96"]` when the field is unset. Pass `[]` (declared empty) to opt out of AAAA filtering entirely. `exclude_a_networks` is consulted only when `64:ff9b::/96` is among the active prefixes.

**Prometheus Metrics:**
- `dns64_synthesised_total` — AAAA queries answered with synthesised records
- `dns64_ptr_translated_total` — `ip6.arpa` PTR queries redirected to `in-addr.arpa`
- `dns64_passthrough_total{reason}` — AAAA queries left untouched, labelled by reason: `aaaa_present`, `nxdomain`, `dnssec_fail`, `no_rd`, `client_excluded`, `zone_excluded`, `cd_bit`, `internal`, `a_excluded`
- `dns64_a_lookup_failures_total{reason}` — failures of the secondary A lookup, labelled by reason

#### EDNS Client Subnet (RFC 7871)

ECS lets a recursive resolver pass a slice of the client's IP to the authoritative server so geo-aware services (CDNs, global load balancers) can return locality-appropriate answers. SDNS supports ECS in two halves, both **opt-in** — by default the resolver strips client-supplied ECS per RFC 7871 §11 privacy guidance.

**Forwarding.** When `[ecs] enabled = true`, the EDNS middleware preserves the client's `EDNS0_SUBNET` option on the outgoing query, clamped down to `forward_v4` / `forward_v6` source-prefix bits so a privacy-leaky client (e.g. one sending its full /32) can't widen the leak beyond the operator's ceiling. The clamped option is stripped from the response before it reaches the client — the wire form only carries it upstream.

**ECS-aware cache.** The cache keys entries by the authority's response SCOPE so a geo-tailored answer for one client subnet isn't served to a client in a different subnet ("cache pollution"). Each `(qname, qtype, qclass, CD)` tuple can hold one shared-key entry (the historical behaviour, used when `SCOPE = 0` or for non-ECS traffic) plus any number of scoped entries. Lookup does longest-prefix-match from the client's source prefix down to `/1`, falling back to the shared key on a scoped miss so SCOPE=0 / pre-1.7.0 entries still hit. Dedup is scope-aware too — two clients in different subnets get separate upstream queries instead of sharing one.

**Configuration:**
```toml
[ecs]
enabled         = false        # default off (RFC 7871 §11)
forward_v4      = 24           # source-prefix ceiling for IPv4
forward_v6      = 56           # source-prefix ceiling for IPv6
client_networks = []           # CIDRs eligible for forwarding; [] = all clients
cache_limit_ttl = "5m"         # max lifetime for scoped cache entries (0 = uncapped)
min_scope_v4    = 24           # refuse to store scopes narrower than this (cardinality cap)
min_scope_v6    = 56
```

`client_networks` is fail-closed: a malformed CIDR or out-of-range knob disables the entire policy (logged at startup) so a typo can't silently re-open forwarding to every client.

**Prometheus Metrics:**
- `dns_cache_ecs_lookups_total{outcome}` — requests that went through the ECS-aware lookup path. `outcome` ∈ `hit_scoped` (scoped probe found the entry), `hit_shared` (scoped missed, shared-key hit — SCOPE=0 or pre-1.7.0 entry), `miss` (both missed). Non-ECS lookups stay on `dns_cache_hits_total` / `dns_cache_misses_total`.

**Operator notes:**
- Scoped entries are never prefetched (the worker has no client IP to derive ECS from). They expire normally; busy scoped names cost an upstream query per TTL window.
- `Purge` (the `/api/v1/purge` endpoint) removes both the shared-key entry and every scoped entry for the qname.
- The full request → upstream → response → cache path is exercised end-to-end by `middleware/cache/cache_ecs_test.go` if you need a usage reference.

#### Recursion Firewall

Bounds aggregate resolver work across one complete request tree — retries, UDP→TCP fallbacks, and nested resolver-generated lookups (DS/DNSKEY, NS addresses, alias targets) all draw from the same budgets, so a single hostile query cannot amplify into unbounded upstream traffic or DNSSEC crypto work.

**Configuration:**
```toml
[recursion_firewall]
mode = "shadow"                  # "off" | "shadow" | "enforce"

max_outbound_queries = 128       # transport attempts per request tree
max_internal_queries = 32        # resolver-generated child queries
max_dnskey_candidates = 4        # same-tag DNSKEY candidates per signature/DS
max_rrset_signature_checks = 8   # signatures tried per RRset
max_signature_checks = 32        # aggregate RRSIG verifications
max_ds_digests = 32              # aggregate DS digest computations
max_nsec3_hashes = 32            # aggregate NSEC3 hash operations
max_concurrent_crypto = 32       # process-wide concurrent crypto operations

failure_cache_size = 4096        # RFC 9520 failure states retained
failure_cache_min_ttl = "5s"     # first-failure backoff interval
failure_cache_max_ttl = "5m"     # backoff ceiling (RFC 9520 bounds: 1s–5m)
```

- `shadow` (the default) records would-be limit crossings in metrics without changing any response. Run it first and calibrate the limits from live traffic before switching to `enforce`.
- `enforce` terminates over-budget request trees with SERVFAIL plus an RFC 8914 Extended DNS Error.
- A limit of 0 means "use the default", not unlimited; disable accounting with `mode = "off"`.
- The RFC 9520 failure cache itself is switched by the top-level `rfc9520` setting, independent of `mode`: failure caching is protocol behaviour, `mode` only governs work accounting.

**Prometheus Metrics:**
- `dns_recursion_firewall_exhaustions_total{reason,mode}` — request trees that crossed a work budget
- `dnssec_work_per_request{operation,mode}` — histogram of DNSSEC operations per request tree; calibrate `enforce` limits from its p99 (especially `nsec3_hashes`)
- `dns_recursion_fanout_ratio` — outbound transport attempts per resolution tree
- `dnssec_work_total{operation,mode}` — aggregate DNSSEC work counters
- `failure_cache_hits_total` — RFC 9520 cached resolution failures served

#### Cache Metrics

SDNS exports comprehensive cache metrics via the Prometheus `/metrics` endpoint for monitoring cache performance.

**Prometheus Metrics:**
- `dns_cache_hits_total` - Total number of cache hits
- `dns_cache_misses_total` - Total number of cache misses
- `dns_cache_evictions_total` - Total number of cache evictions
- `dns_cache_prefetches_total` - Total number of prefetch operations
- `dns_cache_stale_answers_total` - Expired positive answers served after a resolution failure
- `dns_cache_size{type="positive|negative"}` - Current number of entries in the cache. With serve-stale enabled, the positive count includes expired entries retained as stale candidates until eviction
- `dns_cache_hit_rate` - Cache hit rate percentage

**Example Prometheus Queries:**
```promql
# Cache hit rate
dns_cache_hit_rate

# Cache hit ratio (alternative calculation)
rate(dns_cache_hits_total[5m]) / (rate(dns_cache_hits_total[5m]) + rate(dns_cache_misses_total[5m]))

# Total cache size
sum(dns_cache_size)

# Cache operations per second
rate(dns_cache_hits_total[1m]) + rate(dns_cache_misses_total[1m])
```

#### Forwarder upstreams

`forwarderservers` accepts three formats, mix-and-match per entry:

```toml
forwarderservers = [
    "1.1.1.1:53",                          # plain UDP (TCP fallback on TC)
    "tls://1.1.1.1:853",                   # DoT (RFC 7858) — TCP+TLS, IP literal required
    "https://1.1.1.1/dns-query",           # DoH (RFC 8484) — IP literal
    "https://cloudflare-dns.com/dns-query", # DoH — hostname (bootstrapped via system resolver at startup)
]
```

DoH notes:

*   Hostnames are resolved **once at startup** through the system resolver (`/etc/resolv.conf` on Unix). The resolved IPs are pinned for the process lifetime, so there is no per-query DNS dependency. If the upstream changes IPs, restart picks them up.
*   IP-literal DoH URLs skip the bootstrap entirely — safest for hardened deployments that can't depend on the system resolver.
*   POST + `application/dns-message` per RFC 8484, HTTP/2 with connection reuse. The TLS `ServerName` is set to the URL hostname so cert validation works correctly when dialing IPs.
*   Bootstrap failure (NXDOMAIN, timeout, no addresses) is logged and the entry is skipped — startup continues with whatever upstreams remain usable.
*   Timeouts come from the existing top-level config: `querytimeout` caps the **total time** the forwarder spends across every configured upstream (default 10s — applies to UDP, DoT, and DoH alike so three slow upstreams can't take 3 × per-call timeout), `timeout` bounds each per-IP TCP dial inside one DoH attempt (default 2s) so a blackholed pinned address bypasses to the next one without consuming the request budget. Consecutive dial attempts rotate the starting IP so a single bad address can't pin the rotation. Response TXIDs are validated (echo of the request ID or 0 per RFC 8484 §4.1). The existing `dns_forwarder_failures_total` and `dns_forwarder_response_mismatch_total` metrics cover DoH paths too.

#### Per-zone forwarding

`forwarderservers` turns the whole server into a forwarder. `[[forward_zone]]` is the narrow version: one zone goes to its own upstreams while everything else still resolves recursively.

```toml
[[forward_zone]]
name = "corp.example."
servers = ["10.0.0.53:53", "tls://10.0.0.54:853"]

[[forward_zone]]
name = "lab.corp.example."
servers = ["10.0.1.53:53"]
```

*   **The most specific zone wins.** A query for `host.lab.corp.example.` goes to `10.0.1.53`, not to the wider `corp.example.` upstreams.
*   **Servers take the same formats as `forwarderservers`** — plain, `tls://`, and `https://` — so a zone can be forwarded over DoT or DoH.
*   **A zone must name itself and at least one server.** Startup fails otherwise — an omitted `name` canonicalizes to the root, which would quietly forward *every* query and give up local recursion and DNSSEC for everything. Forwarding the root is a real choice, but it has to be written as `name = "."`.
*   **A zone whose upstreams all turn out unusable fails its queries** rather than borrowing `forwarderservers`. Those are public upstreams, and sending an internal zone's questions there is exactly the leak the zone was configured to prevent.
*   **Cached public denials do not shadow a forward zone.** An RFC 8020 subtree cut, aggressive denial or authority failure learned while the name resolved publicly is skipped for a forwarded zone — otherwise a name that does not exist publicly, which is the whole point of an internal zone, would stay NXDOMAIN until the cut expired.
*   **Queries go out with RD=1.** This is forwarding as RFC 8499 §6 defines it: the upstream must be a recursive resolver that answers on your behalf, not the zone's authoritative servers.

> **A forwarded zone is not validated here.** Answers carry whatever the upstream asserted, exactly as in whole-server forwarder mode, and they never enter the RFC 8020/8198 shared denial state — that admission requires proof this resolver validated itself. Pointing a signed public zone at an upstream therefore gives up local DNSSEC validation for it. The intended use is the opposite case: an internal zone the public namespace cannot resolve at all.

### External Plugins

SDNS supports custom plugins to extend its functionality. The execution order of plugins and middlewares affects their behavior. Configuration keys must be strings, while values can be any type. Plugins are loaded before the cache middleware in the order specified.

For implementation details, see the [example plugin](https://github.com/semihalev/sdnsexampleplugin).

**Example Configuration:**
```toml
[plugins]
     [plugins.example]
     path = "/path/to/exampleplugin.so"
     config = {key_1 = "value_1", intkey = 2, boolkey = true, keyN = "nnn"}
     [plugins.another]
     path = "/path/to/anotherplugin.so"
```

## TLS Certificate Management

SDNS automatically monitors and reloads TLS certificates when they change on disk, making it compatible with automatic certificate renewal systems like Let's Encrypt.

### Automatic Certificate Reloading

*   Certificate files are monitored for changes using filesystem notifications
*   When a certificate is updated, SDNS automatically reloads it without dropping connections
*   Works seamlessly with Let's Encrypt and other ACME clients
*   Certificate changes are detected within seconds

### Manual Certificate Reload

You can also trigger a certificate reload manually by sending a SIGHUP signal:

```shell
$ kill -HUP $(pidof sdns)
```

This is useful when:
*   Filesystem notifications are not reliable on your system
*   You want to reload certificates on demand
*   You're using a certificate deployment system that doesn't modify files in-place

### Certificate Requirements

*   Certificate and key files must be readable by the SDNS process
*   Supports standard PEM-encoded X.509 certificates
*   Works with wildcard certificates
*   Compatible with both RSA and ECDSA certificates

## Server Configuration Checklist

*   Increase the file descriptor limit on your server

## Features

*   Linux/BSD/Darwin/Windows support
*   Full DNS RFC compatibility
*   DNS queries using both IPv4 and IPv6 authoritative servers
*   High-performance DNS caching with prefetch support
*   Serve-stale as a last resort on resolution failure (RFC 8767), bounded by the learned delegation lease
*   Full DNSSEC validation support with RFC 8914 Extended DNS Errors (EDE)
*   DNS over TLS (DoT) support
*   DNS over HTTPS (DoH) support with HTTP/3
*   DNS over QUIC (DoQ) support
*   Multiple outbound IP selection for queries
*   Extensible middleware architecture
*   RTT-based server prioritization with adaptive timeouts
*   Parallel DNS lookups for improved performance
*   Failover to backup servers on failure
*   DNS forwarding support, including per-zone conditional forwarding
*   EDNS Client Subnet forwarding with scoped caching (RFC 7871)
*   EDNS Cookie support (RFC 7873)
*   EDNS NSID support (RFC 5001)
*   Extended DNS Errors (EDE) support (RFC 8914)
*   Full IPv6 support (both client and server communication)
*   Query-based rate limiting
*   Client IP-based rate limiting
*   IP-based access control lists
*   Response Policy Zones (RPZ): QNAME, client-address, and answer-address triggers; shadow mode; per-zone overrides; file and TSIG-signed AXFR feeds
*   Comprehensive access logging
*   Prometheus metrics with optional per-domain tracking
*   DNS sinkholing for malicious domains
*   HTTP API for management and statistics
*   Cache purge via API and DNS queries
*   Chaos TXT query support for version.bind and hostname.bind
*   Empty zones support (RFC 1918)
*   External plugin support
*   Binary DNS logging via dnstap protocol (RFC 6742)
*   QNAME minimization for privacy (RFC 9156)
*   Hyperlocal root zone (RFC 8806) with ZONEMD verification (RFC 8976)
*   Per-client views: static answers scoped to client networks
*   Recursion work firewall: per-request-tree budgets on outbound queries, internal work, and DNSSEC operations, with shadow and enforce modes
*   Automatic DNSSEC trust anchor updates (RFC 5011)
*   Zero-allocation cache operations for improved performance
*   **Owned UDP/TCP/DoT serving engine: wire-eligible warm cache hits answered from raw bytes, allocation-free per query on UDP and TCP (DoT rides the same path; TLS record buffers are the runtime's), with batched `recvmmsg`/`sendmmsg` I/O on Linux — composite answers that need message shaping take the ordinary path**
*   **Self-sizing serving bounds derived from the machine's memory (cgroup and GOMEMLIMIT aware) — the same binary fits a 32-core server and a 128MB router**
*   TCP connection pooling for persistent connections
*   **Kubernetes DNS integration with a 256-way sharded registry and zero-allocation lookups**
*   **Automatic TLS certificate reloading without downtime**
*   **DNS amplification/reflection attack detection (Reflex)**
*   **DNS64 synthesis for IPv6-only clients (RFC 6147)**

## Performance

Throughput measurements, methodology, resolver comparisons and their caveats
live in [BENCHMARKS.md](BENCHMARKS.md) — measured with dnsperf against
PowerDNS Recursor, Unbound and Knot Resolver under identical load, most
recently for the 1.8.0 serving-path work.

For Kubernetes DNS, the registry is the hot path:

- `BenchmarkRegistryResolveQuery` reports **0 B/op, 0 allocs/op** at
  ~95 ns/op on Apple M5 — every query is a single sharded map lookup
  followed by a slice-header copy.
- Each mutation (`AddService`/`AddPod`/`SetEndpoints`) pre-builds the
  `dns.RR` slices the affected names will return, including SRV
  per named port and PTR for ClusterIPs / pod IPs.
- The full `ServeDNS` path adds the unavoidable `dns.Msg` setup and
  wire-pack overhead from miekg/dns; that's the only remaining
  per-query allocation cost.

> The legacy `killer_mode` flag is still parsed for backward
> compatibility but is now a no-op — the registry above is always
> active. The previous "killer mode" components (per-package cache,
> SmartPredictor, PrefetchStrategy) were removed.

## Contributing

We welcome pull requests. If you're considering significant changes, please start a discussion by opening an issue first.

Before submitting patches, please review our [CONTRIBUTING](https://github.com/semihalev/sdns/blob/main/CONTRIBUTING.md) guidelines.

## :hearts: Made With

*   [miekg/dns](https://github.com/miekg/dns) - Alternative (more granular) approach to a DNS library

## Inspired by

*   [looterz/grimd](https://github.com/looterz/grimd)

## License

[MIT](https://github.com/semihalev/sdns/blob/main/LICENSE)
