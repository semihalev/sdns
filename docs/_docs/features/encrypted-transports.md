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

`binddoh` opens two listeners on the same address: HTTP/1 and HTTP/2 over TCP,
and HTTP/3 over UDP. Replies over HTTP/1 and HTTP/2 carry an `Alt-Svc` header
naming `h3` on the port the request arrived on, so clients move to HTTP/3 on
their own. Open UDP as well as TCP on the DoH port so they can reach it.

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
every five minutes in case an event is missed. Either way it reloads when the
certificate file's modification time has moved forward; a new key under an
unchanged certificate is not picked up, so replace the key first and the
certificate last, or send `SIGHUP`, which forces an immediate reload. A
replacement that fails to load leaves the previous certificate in place.

## Which clients reach which

**DoT** is what mobile operating systems and system resolvers speak. It is the
one to enable if you want ordinary devices to use your resolver privately.

**DoH** is what browsers speak. It shares port 443 with HTTPS, which is the
point. It is indistinguishable from ordinary web traffic on the wire. A web
page on any origin may query it: every reply allows any origin, and the
preflight a page sends before a POST is answered with GET and POST allowed.

**DoQ** is the newest and least widely supported. It avoids the head-of-line
blocking DoT inherits from TCP. sdns follows RFC 9250 as written: it offers
only the `doq` ALPN token, not the drafts', and closes a connection that sends
a non-zero message ID or anything else the RFC names a protocol error. Each
stream is served on its own, from the same byte path as UDP and TCP; one a
busy server cannot take is reset with `DOQ_EXCESSIVE_LOAD`, which a client
retries, and a stream the client abandons costs only that stream.

## TLS

DoT and DoH over HTTP/1 and HTTP/2 accept TLS 1.2 or later. DoQ requires TLS
1.3, and DoH over HTTP/3 runs on QUIC, which is TLS 1.3 only.

sdns sets no key exchange preferences of its own and uses the Go defaults. A
peer that offers the hybrid post-quantum X25519MLKEM768 key exchange gets it,
and any other peer gets a classical group, X25519 when it offers that and
otherwise one of the NIST curves such as P-256. This holds on every encrypted
listener and on the forwarder's DoT and DoH upstreams.

A client that pads its query (RFC 7830) over an encrypted transport gets a
reply padded to a multiple of 468 bytes, the block size RFC 8467 recommends,
so the reply's length says less about what it contains. A client that does not
pad gets no padding.

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
section, as sdns resolves them, never the hints. They are optional: the A and
AAAA lookups share one second between them, and what is not back by then, or a
set that would not fit the client's buffer, is left out rather than waited for
or allowed to truncate the answer.

A hint must be a global unicast address of its list's family. `sdns -t`
refuses loopback, link-local, multicast and unspecified addresses, the IPv4
limited broadcast, an address with a zone, an IPv4 address in `ipv6hint` or
the reverse, and an address listed twice. A private address is accepted: it is
a fine hint for a resolver on a home or office network.

A listener bound to a loopback address is not advertised: a client would only
ever reach its own machine there. The one exception is DoH with `doh_port`
set, described below, where a proxy publishes the loopback listener. A
listener on several addresses is advertised once per port: the addresses are
not in the records, so two on one port are one record, and a loopback address
among them is simply left out. Only listeners that are actually up are
advertised: one whose port was taken at startup is left out, and DoH offers
HTTP/3 only while its own QUIC listener is serving, unless `doh_port` or
`doh_alpn` is set. The DoT listener selects the `dot` ALPN for a client that
asks for it, and connects older clients that do not exactly as before.

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
the advertised name. The proxy's offer replaces the listener's: each ALPN in
`doh_alpn` is advertised while the DoH listener's TCP side is up, since that is
what the proxy reaches. Left empty, `doh_alpn` takes the listener's own, `h2`
and `h3`, so set it whenever the proxy does not serve HTTP/3. Discovering
clients speak HTTP/2 to DoH, so the proxy must serve it: with nginx,
`http2 on;` in the server block.

`sdns -t` refuses an enabled `[ddr]` with no encrypted listener to point at,
or with no usable name: an empty `name` and a certificate that carries IP
addresses only, a `name` that is not a domain name, or one under
`resolver.arpa`. It also refuses a `doh_port` outside 0 to 65535, a `doh_alpn`
entry other than `"h2"` or `"h3"`, or one listed twice, and either key without
a DoH listener to publish.

Whether discovery is on or not, every name under `resolver.arpa` is answered by
sdns itself and never sent upstream, as the RFC requires: an upstream's answer
would describe the upstream's listeners, not yours. The zone is served locally:
its apex answers its SOA and NS as data, and any other name or type in it gets
NODATA with the SOA in the authority section. Only class IN is answered this
way; a query in another class gets the answer any other class does, see
[Query classes]({{ '/docs/configuration/resolution/' | relative_url }}#query-classes).

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
that never opened the port: TCP 853 for DoT, UDP 853 for DoQ, TCP 443 for DoH
and UDP 443 for DoH over HTTP/3.

## Watching it

```
dns_doh_http_errors_total     HTTP-level failures on the DoH listener
dns_listener_errors_total     listener errors, by transport
dns_tcp_ingress_drops_total   TCP and DoT events dropped before the handler, by reason
dns_doq_ingress_drops_total   DoQ connections and streams refused, by reason
```

A rising `reason="conncap"` on either drop counter means clients are being
turned away at the connection cap.

## Access control still applies

`accesslist` is enforced on every transport. Enabling DoH does not create a
second door into the resolver with different rules, a client refused on UDP is
refused over HTTPS too.
