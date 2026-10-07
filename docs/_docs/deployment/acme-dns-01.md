---
layout: doc
title: ACME DNS-01 challenges
category: Deployment
order: 5
description: Keep service names local while Let’s Encrypt validates public challenge records.
---

DNS-01 lets you obtain certificates for private services using a public domain
name you control. The service can stay on a private address: validation depends
on a public TXT record, without an inbound connection to the service. An
owner-authoritative view keeps service answers local, while an exact CNAME alias
lets challenge lookups reach public DNS.

The examples assume an existing working resolver. Replace `example.com`,
`example.net` and the network addresses with your own domains and addresses.

## Two DNS paths

In an automated DNS-01 setup, the ACME client requests the certificate and uses
your DNS provider to publish and remove challenge TXT records. sdns answers the
client's DNS queries.

The client may check that the value is visible before asking Let’s Encrypt to
validate. Let’s Encrypt independently looks it up through public DNS, so a
successful local check needs a matching public configuration.
[Let’s Encrypt accepts CNAME delegation](https://letsencrypt.org/docs/challenge-types/#dns-01-challenge),
so the TXT can live at a separate validation name.

For this example, the lookup paths are:

```text
Local service:
  app.example.com → sdns → 192.168.1.10

Client challenge check:
  _acme-challenge.example.com → sdns → CNAME challenge.example.net
  challenge.example.net TXT → sdns → public DNS

Let’s Encrypt validation:
  _acme-challenge.example.com → public DNS → CNAME challenge.example.net
  challenge.example.net TXT → public DNS → current challenge value
```

## Keep service answers local

An A-only overlay can leave other types resolving publicly. A client might
receive a private address alongside HTTPS records describing a public CDN,
including its Encrypted Client Hello (ECH) configuration. Owner-authoritative
mode keeps matching names local across record types: configured records are
returned, and absent types receive NOERROR/NODATA, meaning the lookup succeeded
but that type has no answer.

That also covers `_acme-challenge.example.com`. Without an exception, its TXT
lookup would receive NODATA. Add an exact CNAME in the same view:

```toml
[[views]]
zone = "local-services"
mode = "authoritative-owner"
networks = ["192.168.1.0/24"]
answers = [
    "*.example.com. 60 IN A 192.168.1.10",
    "*.example.com. 60 IN HTTPS 1 . alpn=\"h2,http/1.1\" ipv4hint=192.168.1.10",
    "_acme-challenge.example.com. 60 IN CNAME challenge.example.net.",
]
```

The HTTPS record describes the local endpoint and contains no public ECH
configuration. Set `alpn` to the protocols your service supports, or omit the
HTTPS record to return NODATA for HTTPS. Validate your complete configuration
with `sdns -t -c /path/to/sdns.conf` before applying it.

The exact challenge owner takes precedence over the wildcard, including for TXT
queries. sdns returns its CNAME without looking up the target. The ACME client
must follow the alias and query the target itself.

Put these records in the first view whose networks match the client; later
matching views are not consulted. `zone` identifies the view, not a DNS zone.
Include the source address sdns sees from a container or VPN. Keep the challenge
name out of hosts-file answers, which run before views.
[Views and forwarding]({{ '/docs/features/views/' | relative_url }}) explains this
selection order.

Choose a target outside the locally owned wildcard. Here,
`challenge.example.net` is outside `*.example.com`, so its lookup proceeds
normally. Check that no other owner-authoritative view, hosts entry or blocking
policy captures the target.

## Publish the matching public records

Create this permanent record at the public DNS provider for `example.com`:

```dns
_acme-challenge.example.com. 60 IN CNAME challenge.example.net.
```

Use the same CNAME target in sdns and public DNS. Let’s Encrypt finds the public
alias; the local alias lets the client's sdns lookup follow it. Keep the alias
DNS-only where your provider offers proxying, and do not place TXT or other
ordinary records alongside the CNAME at that owner. TTLs are illustrative;
providers may enforce different minimums.

Configure a DNS-01 client that supports delegation and publishes TXT records at
the target. Give it provider access to update the `example.net` validation
zone. Some clients follow CNAMEs automatically; others require explicit
configuration. See [Lego’s CNAME support](https://go-acme.github.io/lego/advanced/options/index.html#lego_disable_cname_support)
or [Caddy’s TLS settings](https://caddyserver.com/docs/caddyfile/directives/tls).

For checks through sdns, point the client's recursive-resolver setting at your
sdns listener, or use sdns as its system resolver. Clients may also query
authoritative servers directly; follow the client's documentation for those
checks.

During validation, public DNS at `challenge.example.net` must return the current
challenge TXT value. The client publishes it through the provider; do not copy
it into sdns. It must preserve simultaneous challenge values and remove only
its own records when finished.

### Optional TXT marker

Optionally, create a persistent TXT marker before publishing the alias. This
marker is not a challenge value and reduces new negative-cache entries between
issuances:

```dns
challenge.example.net. 60 IN TXT "acme-delegation-ready"
```

Confirm your client preserves the marker when creating and cleaning up tokens.
It cannot invalidate an already cached negative answer.

## Match the certificate names

The domain itself, or apex, is `example.com`. Both it and `*.example.com` use
`_acme-challenge.example.com`, so this exception supports a certificate
containing both names. They can require different TXT values at the same target
during one issuance.

An individual certificate for `app.example.com` uses
`_acme-challenge.app.example.com`. Add a corresponding exact CNAME in the local
view and public DNS, with a publicly resolvable target your client can update.
The apex exception does not cover every certificate name below it.

sdns’s wildcard matches nested names such as `deep.app.example.com`, but a TLS
certificate for `*.example.com` covers only one label below `example.com`.
Include the apex separately if needed. The DNS wildcard excludes the apex, so
this example leaves `example.com` resolving normally.

## Verify before issuance

Run these from the ACME client’s network, using your sdns address:

```bash
dig @192.168.1.1 app.example.com A +noall +answer
dig @192.168.1.1 app.example.com HTTPS +noall +answer
dig @192.168.1.1 app.example.com SVCB +noall +comments +answer
dig @192.168.1.1 _acme-challenge.example.com TXT +noall +answer
dig @192.168.1.1 challenge.example.net TXT +noall +comments +answer
```

Expect the local address and HTTPS record, NODATA for SVCB, and the exact CNAME
for the challenge TXT query. Query the target separately: the local CNAME reply
does not contain its TXT data.

Before issuance, the target may contain only the marker, or no TXT if you omitted
it. An empty lookup can cache a negative answer; allow its negative TTL to expire
before issuance. During issuance, the target must contain the current expected
challenge value. A marker or old token is insufficient.

Check the public alias and target from an independent DNS path too:

```bash
dig @1.1.1.1 _acme-challenge.example.com CNAME +noall +answer
dig @1.1.1.1 challenge.example.net TXT +noall +comments +answer
```

If your network intercepts port 53, run public checks from an unaffected
network. A custom recursive resolver only helps with client checks sent to it;
direct authoritative-server queries can still be intercepted. If your client
supports separate controls, bypass only unreachable authoritative checks and
retain checks for the expected TXT through a working resolver. Follow its
documentation for those options.

## Caching and renewal

Public TXT answers and negative responses can remain cached after a provider
update. Negative lifetimes come from the public zone’s SOA record and are
separate from the local alias TTL. Set propagation waits and timeouts for your
provider and observed cache lifetimes. A longer timeout does not refresh an
answer immediately. See [Cache and TTLs]({{ '/docs/configuration/cache/' | relative_url }}).

First obtain a certificate for `example.com` and `*.example.com` using
[Let’s Encrypt staging](https://letsencrypt.org/docs/staging-environment/) with a
separate account and storage. Verify cleanup leaves the delegation and any
marker intact, then configure production issuance and automatic renewal.
Staging certificates are untrusted and should stay out of the production
certificate store.

If you persist or restore sdns's cache, also test with warm caches and after a
restore. Use a fresh staging account for each repeat so existing authorizations
do not skip the challenge.
