---
layout: doc
title: Encrypted transports
category: Features
order: 9
description: Serving DNS over TLS, HTTPS and QUIC.
---

sdns serves DoT, DoH and DoQ alongside plain UDP and TCP, from the same cache
and the same resolver. All three are off until you configure a listener and TLS
material.

```toml
bindtls = ":853"                       # DNS over TLS   (RFC 7858)
binddoh = ":443"                       # DNS over HTTPS (RFC 8484)
binddoq = ":853"                       # DNS over QUIC  (RFC 9250)

tlscertificate = "/etc/sdns/fullchain.pem"
tlsprivatekey  = "/etc/sdns/privkey.pem"
```

`bindtls` and `binddoq` can share port 853: one is TCP, the other UDP.

## Certificates

Both files are PEM. Use the full chain for the certificate, not just the leaf,
clients that cannot build a path to a trusted root will refuse the connection,
and a DoT client failing that way looks like an outage rather than a
misconfiguration.

`sdns -t` opens both files, so a wrong path or a key the service user cannot
read is caught before the restart.

Certificates do not need a restart to renew. sdns watches the directories
holding both files with fsnotify, directories rather than the files
themselves, so an ACME client swapping a symlink is noticed, and re-checks
every five minutes in case an event is missed. `SIGHUP` forces an immediate
reload. A replacement that fails to load leaves the previous certificate in
place.

## Which clients reach which

**DoT** is what mobile operating systems and system resolvers speak. It is the
one to enable if you want ordinary devices to use your resolver privately.

**DoH** is what browsers speak. It shares port 443 with HTTPS, which is the
point. It is indistinguishable from ordinary web traffic on the wire.

**DoQ** is the newest and least widely supported. It avoids the head-of-line
blocking DoT inherits from TCP.

## Letting clients find them

A device configured with your resolver's IP address speaks plain DNS to it and
has no way to know the encrypted listeners exist. Discovery of Designated
Resolvers (RFC 9462) closes that gap: the client asks `_dns.resolver.arpa` for
SVCB records, learns which transports you serve, and upgrades on its own.
Current Windows, macOS, iOS and Android releases all do this.

```toml
[ddr]
enabled = true
name    = ""        # empty takes the certificate's first DNS name
```

sdns answers with one record per listener you configured, in the order DoH,
DoT, DoQ, each with its ALPN, its port when it is not the transport's default,
and for DoH the path template `/dns-query{?dns}`. Address hints are carried
only when you set them, `ipv4hint` and `ipv6hint` under `[ddr]`, and never
taken from a listener's bind address: behind a load balancer, NAT, anycast or
a reverse proxy the address sdns is bound to is not the one clients reach.
Without hints clients resolve the advertised name, which must then point at
where they connect; with them they can connect without that lookup. The
answer also carries the name's own A and AAAA records in its Additional
section, as sdns resolves them, never the hints. They are optional: a lookup
that is not back within a second, or a set that would not fit the client's
buffer, is left out rather than waited for or allowed to truncate the answer. A private
address is a fine hint for a resolver on a home or office network; anything
that is not global unicast, loopback, link-local, multicast, unspecified or
the IPv4 limited broadcast, is refused by `sdns -t`. A listener bound
to a loopback address is not advertised at all: a client would only ever
reach its own machine there.
Only listeners that are actually up are
advertised: one whose port was taken at startup is left out, and DoH offers
HTTP/3 only while the QUIC listener is serving. The DoT listener selects the
`dot` ALPN for a client that asks for it, and connects older clients that do
not exactly as before.

**The certificate decides whether it works.** A client upgrades only after
checking that the certificate on the encrypted listener lists, in its
subjectAltName, the IP address it was using for plain DNS. A certificate that
names the server only by hostname passes `sdns -t` and is never used by
discovering clients, so issue one with the resolver's IP addresses on it. The
advertised name is the one the certificate or `name` gives at startup; a
renewed certificate with a different first name takes effect at the next
restart, so set `name` if it should never move.

**DoH behind a reverse proxy.** When DoH is bound to loopback and a proxy
publishes it, say nginx on 443 forwarding to `127.0.0.1:8053`, tell discovery
what the proxy offers:

```toml
[ddr]
enabled  = true
doh_port = 443      # the proxy's port; 443 is the default and is not carried
doh_alpn = ["h2"]   # what the proxy serves; add "h3" only if it serves HTTP/3
```

The record then carries the proxy's port, and clients find the proxy through
the advertised name. Discovering clients speak HTTP/2 to
DoH, so the proxy must serve it: with nginx, `http2 on;` in the server block.

`sdns -t` refuses an enabled `[ddr]` with no encrypted listener to point at,
or with no usable name: an empty `name` and a certificate that carries IP
addresses only.

Whether discovery is on or not, every name under `resolver.arpa` is answered by
sdns itself and never sent upstream, as the RFC requires: an upstream's answer
would describe the upstream's listeners, not yours. Anything but the discovery
record gets NODATA.

```bash
dig @resolver.example _dns.resolver.arpa SVCB
```

## What to check after enabling

```bash
# DoT
kdig @resolver.example +tls example.com A

# DoH
curl -H 'accept: application/dns-message' \
  'https://resolver.example/dns-query?dns=<base64url-query>'
```

If the plain-DNS listener still answers and the encrypted one does not, the
usual causes are a certificate chain the client will not accept, or a firewall
that never opened 853.

## Watching it

```
dns_doh_http_errors_total   HTTP-level failures on the DoH listener
dns_listener_errors_total   listener errors, by transport
```

## Access control still applies

`accesslist` is enforced on every transport. Enabling DoH does not create a
second door into the resolver with different rules, a client refused on UDP is
refused over HTTPS too.
