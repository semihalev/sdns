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

Both files are PEM. Use the full chain for the certificate, not just the leaf —
clients that cannot build a path to a trusted root will refuse the connection,
and a DoT client failing that way looks like an outage rather than a
misconfiguration.

`sdns -t` opens both files, so a wrong path or a key the service user cannot
read is caught before the restart.

Certificates do not need a restart to renew. sdns watches the directories
holding both files with fsnotify — directories rather than the files
themselves, so an ACME client swapping a symlink is noticed — and re-checks
every five minutes in case an event is missed. `SIGHUP` forces an immediate
reload. A replacement that fails to load leaves the previous certificate in
place.

## Which clients reach which

**DoT** is what mobile operating systems and system resolvers speak. It is the
one to enable if you want ordinary devices to use your resolver privately.

**DoH** is what browsers speak. It shares port 443 with HTTPS, which is the
point — it is indistinguishable from ordinary web traffic on the wire.

**DoQ** is the newest and least widely supported. It avoids the head-of-line
blocking DoT inherits from TCP.

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
second door into the resolver with different rules — a client refused on UDP is
refused over HTTPS too.
