package config

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/miekg/dns"

	"github.com/semihalev/sdns/internal/emptyzones"
	"github.com/semihalev/sdns/internal/rpz"
)

// Validate reports what is wrong with a loaded configuration.
//
// Every problem is collected and reported together. An operator fixing a
// config file wants the whole list, not one error per run — and a DNS server
// that refuses to start is a visible failure, where one that starts with a
// setting it silently ignored is not.
//
// The rules only reject what cannot be right: an address that does not parse,
// a value outside an enumerated set, a file that is not there. Anything this
// package cannot judge — whether an upstream answers, whether a certificate
// matches its key — belongs to the component that uses it.
func (c *Config) Validate() error {
	var problems []string
	add := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	switch c.DNSSEC {
	case "", "on", "off":
	default:
		// Anything but "off" silently became "on", so a typo here turned
		// validation on when the operator meant to turn it off.
		add("dnssec = %q: must be \"on\" or \"off\"", c.DNSSEC)
	}

	// Exactly what startup accepts: the four levels, plus omission, which is
	// filled in as "info" before the logger sees it. Anything else stops the
	// server there, so a config test that disagreed would send the operator
	// to production with a file that cannot start. "crit" was documented for
	// years but never existed — the logger has no such level and startup
	// rejects it.
	switch c.LogLevel {
	case "", "debug", "info", "warn", "error":
	default:
		add("loglevel = %q: must be one of debug, info, warn, error", c.LogLevel)
	}

	for _, bind := range []struct {
		key, value string
		networks   []string
	}{
		// The plain listener answers over both; the rest open one apiece.
		{"bind", c.Bind, []string{"udp", "tcp"}},
		{"bindtls", c.BindTLS, []string{"tcp"}},
		// DoH brings its HTTP/3 listener with it, on UDP at the same address.
		{"binddoh", c.BindDOH, []string{"udp", "tcp"}},
		{"binddoq", c.BindDOQ, []string{"udp"}},
	} {
		if bind.value == "" {
			continue
		}
		host, port, err := net.SplitHostPort(bind.value)
		switch {
		case err != nil || port == "":
			add("%s = %q: must be host:port", bind.key, bind.value)
		default:
			// The host half is deliberately not judged. Empty means every
			// interface; a literal may name an address this machine does not
			// hold yet, which is how a floating address is served; and
			// whether a name resolves is a runtime question of the same
			// class as whether an upstream answers.
			_ = host
			n, err := usablePort(port, bind.networks...)
			switch {
			case err != nil:
				add("%s = %q: %v", bind.key, bind.value, err)
			case n == 0 && len(bind.networks) > 1:
				// Port 0 asks the kernel for a free one, and each socket
				// asks separately: the two transports of this setting would
				// land on different ports, so a truncated UDP answer has no
				// TCP to fall back to — and DoH would advertise ":0" as its
				// HTTP/3 port. Fine where the setting opens one socket.
				add("%s = %q: port 0 gives each transport a different port; name one", bind.key, bind.value)
			}
		}
	}

	if c.BindTLS != "" || c.BindDOH != "" || c.BindDOQ != "" {
		if c.TLSCertificate == "" || c.TLSPrivateKey == "" {
			add("tlscertificate and tlsprivatekey are required when bindtls, binddoh or binddoq is set")
		} else {
			for _, f := range []struct{ key, path string }{
				{"tlscertificate", c.TLSCertificate},
				{"tlsprivatekey", c.TLSPrivateKey},
			} {
				if err := regularFile(f.path); err != nil {
					add("%s = %q: %v", f.key, f.path, err)
				}
			}
		}
	}

	// Blocked names answer A from the first and AAAA from the second. Swap
	// them and the A record packs the IPv6 address's nil To4() as 0.0.0.0,
	// while the AAAA carries an IPv4-mapped address — a wrong answer rather
	// than a failure, so nothing downstream complains.
	for _, ip := range []struct {
		key, value string
		want4      bool
	}{
		{"nullroute", c.Nullroute, true},
		{"nullroutev6", c.Nullroutev6, false},
	} {
		if ip.value == "" {
			continue
		}
		parsed := net.ParseIP(ip.value)
		switch {
		case parsed == nil:
			add("%s = %q: must be an IP address", ip.key, ip.value)
		case (parsed.To4() != nil) != ip.want4:
			family := "IPv6"
			if ip.want4 {
				family = "IPv4"
			}
			add("%s = %q: must be %s", ip.key, ip.value, family)
		}
	}

	for _, entry := range c.AccessList {
		// The access list is parsed with netip.ParsePrefix and nothing else,
		// so a bare address is dropped at startup. Accepting one here would
		// pass a file whose only entry is discarded — leaving an empty allow
		// set, which blocks every client.
		if !validCIDR(entry) {
			add("accesslist %q: must be a CIDR block, e.g. 192.0.2.0/24 or 192.0.2.1/32", entry)
		}
	}

	root6 := c.Root6Servers
	if !c.IPv6Access {
		root6 = nil
	}

	// The resolver takes IPv4 from rootservers and IPv6 from root6servers,
	// and silently drops anything in the wrong list. A misplaced address
	// therefore leaves a shorter root set than the operator wrote, or an
	// empty one.
	for _, list := range []struct {
		key    string
		values []string
		want   string // "4", "6", or "" for either
	}{
		{"rootservers", c.RootServers, "4"},
		// Only read behind ipv6access, so a stale entry on a host without
		// v6 has no effect and must not stop the server.
		{"root6servers", root6, "6"},
		{"fallbackservers", c.FallbackServers, ""},
	} {
		for _, addr := range list.values {
			host, port, err := net.SplitHostPort(addr)
			if err != nil || port == "" {
				add("%s %q: must be an IP address and port, e.g. 192.0.2.1:53", list.key, addr)
				continue
			}
			ip := net.ParseIP(host)
			if ip == nil {
				add("%s %q: must be an IP address and port, e.g. 192.0.2.1:53", list.key, addr)
				continue
			}
			// Unlike a listener, an upstream cannot use port 0: nothing
			// answers there, and the dial failure is per query rather than
			// at startup.
			if n, err := usablePort(port, "udp", "tcp"); err != nil || n == 0 {
				add("%s %q: must have a port to reach, e.g. 192.0.2.1:53", list.key, addr)
				continue
			}
			is4 := ip.To4() != nil
			if (list.want == "4" && !is4) || (list.want == "6" && is4) {
				add("%s %q: must be an IPv%s address", list.key, addr, list.want)
			}
		}
	}

	for _, addr := range c.ForwarderServers {
		if err := validUpstream(addr); err != nil {
			add("forwarderservers %q: %v", addr, err)
		}
	}
	for i := range c.ForwardZones {
		zone := &c.ForwardZones[i]
		for _, addr := range zone.Servers {
			if err := validUpstream(addr); err != nil {
				add("forward_zone %q server %q: %v", zone.Name, addr, err)
			}
		}
	}

	for _, d := range []struct {
		key   string
		value Duration
	}{
		{"timeout", c.Timeout},
		{"querytimeout", c.QueryTimeout},
	} {
		if d.value.Duration < 0 {
			add("%s = %q: must not be negative", d.key, d.value.Duration)
		}
	}

	for _, n := range []struct {
		key   string
		value int
	}{
		// Zero keeps its "use the default" meaning; a size the cache would
		// silently raise is caught below.
		{"cachesize", c.CacheSize},
		{"maxdepth", c.Maxdepth},
		{"ratelimit", c.RateLimit},
		{"clientratelimit", c.ClientRateLimit},
		{"maxconcurrentqueries", c.MaxConcurrentQueries},
		// Each of these treats zero as "use the default", so a negative
		// value is neither the default nor what was asked for: it leaves the
		// TCP pool holding nothing, dnstap back on its default interval, and
		// the metrics limit meaningless.
		{"dnstapflushinterval", c.DnstapFlushInterval},
		{"domainmetricslimit", c.DomainMetricsLimit},
		{"ingressworkers", c.IngressWorkers},
		{"ingressqueue", c.IngressQueue},
		{"ingresstcpconns", c.IngressTCPConns},
	} {
		if n.value < 0 {
			add("%s = %d: must not be negative", n.key, n.value)
		}
	}

	// Only reachable behind tcpkeepalive: the pool is the only reader, and it
	// is not built at all when the setting is off.
	if c.TCPKeepalive {
		for _, d := range []struct {
			key   string
			value Duration
		}{
			{"roottcptimeout", c.RootTCPTimeout},
			{"tldtcptimeout", c.TLDTCPTimeout},
		} {
			if d.value.Duration < 0 {
				add("%s = %q: must not be negative", d.key, d.value.Duration)
			}
		}
		if c.TCPMaxConnections < 0 {
			add("tcpmaxconnections = %d: must not be negative", c.TCPMaxConnections)
		}
	}

	// Everything the load path used to check on its own runs here too, so one
	// pass reports every problem in the file rather than one problem per run.
	//
	// An empty firewall mode is the operator omitting the section; Normalize
	// fills it in before the load path reaches here, so only a mode that
	// survived normalization is judged. Validating "" would fail every Config
	// built in code rather than read from a file.
	if c.RecursionFirewall.Mode != "" {
		if err := c.RecursionFirewall.Validate(); err != nil {
			add("invalid recursion firewall config: %v", err)
		}
	}
	if c.ServeStaleMaxTTL.Duration < 0 {
		add("serve_stale_max_ttl must not be negative (got %q)", c.ServeStaleMaxTTL.Duration)
	}
	c.validateForwardZones(add)
	c.validateTrustAndIdentity(add)
	c.validateNameLists(add)
	c.validateSubTables(add)
	c.validateRPZ(add)

	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("invalid configuration:\n  - %s", strings.Join(problems, "\n  - "))
}

// validateTrustAndIdentity covers the settings that decide who this resolver
// trusts and what address it speaks from.
func (c *Config) validateTrustAndIdentity(add func(string, ...any)) {
	// Syntax alone does not make a usable root anchor, and every way of
	// getting it wrong fails somewhere the operator will not connect to
	// this file: a malformed record is fatal at resolver construction, a
	// record that is not a DNSKEY panics an unchecked type assertion during
	// verification, and a key that is merely not a root KSK leaves the
	// anchor set empty so every DNSSEC answer fails on unavailable anchors.
	// Every record is parsed whatever the settings — NewResolver stops the
	// process on one that will not — but nothing looks at what a record
	// means unless validation or the hyperlocal root asks it to. Judging the
	// meaning regardless would refuse a stale key that has no effect.
	anchorsUsed := c.DNSSEC == "on" || c.HyperlocalRoot

	anchors := 0
	for _, key := range c.RootKeys {
		rr, err := dns.NewRR(key)
		if err != nil {
			add("rootkeys %q: %v", key, err)
			continue
		}
		if !anchorsUsed {
			continue
		}
		dnskey, ok := rr.(*dns.DNSKEY)
		if !ok {
			add("rootkeys %q: must be a DNSKEY record", key)
			continue
		}
		switch {
		case dns.CanonicalName(dnskey.Hdr.Name) != ".":
			add("rootkeys %q: must be owned by the root zone", key)
		case dnskey.Hdr.Class != dns.ClassINET:
			add("rootkeys %q: must be class IN", key)
		case dnskey.Protocol != 3:
			add("rootkeys %q: protocol must be 3 (RFC 4034 section 2.1.2)", key)
		case dnskey.Flags&dnsKeyFlagRevoke != 0 && dnskey.Flags&^dnsKeyFlagRevoke == 257:
			// RFC 5011 section 2.1: an operator may seed a revoked key so
			// the resolver remembers the revocation across a restart. AutoTA
			// records it as a tombstone and keeps it out of the active set,
			// which is exactly what not counting it here does.
			//
			// The REVOKE bit rides on top of the key-signing flags; on its
			// own it is not a KSK, and AutoTA drops such a record before it
			// ever looks at the bit.
		case dnskey.Flags != 257:
			// Only key-signing keys enter the verification set.
			add("rootkeys %q: must be a key-signing key (flags 257), not %d", key, dnskey.Flags)
		default:
			// Nothing rejects an unusable key at startup: the anchor is
			// loaded, and then every signature it is asked to verify fails,
			// so validation is off while the file still says it is on.
			if problem := anchorKeyProblem(dnskey); problem != nil {
				add("rootkeys %q: %v", key, problem)
				continue
			}
			anchors++
		}
	}
	switch {
	case anchors == 0 && c.HyperlocalRoot:
		// The manager verifies every transfer against these and gives up on
		// each refresh while there are none, so the feature never produces a
		// snapshot at all. Forwarding does not excuse it: the manager runs
		// whatever the query path does.
		add("rootkeys: hyperlocal_root has no trust anchor to verify a transfer against, so it can never load the zone")
	case anchors == 0 && c.DNSSEC == "on" && len(c.ForwarderServers) == 0 && !c.forwardsRoot():
		// AutoTA needs a seed and will not take one from disk when the live
		// set is empty, so this does not heal on its own: every iterative
		// validation fails closed from the first query. A global forwarder
		// skips the resolver entirely and so needs no anchor of its own —
		// and neither does a forward zone at the root, which hands every
		// query to its upstreams by the same early return.
		add("rootkeys: dnssec is on with no usable root trust anchor, so every validated answer would fail")
	case anchorsUsed && anchors == 0 && len(c.RootKeys) > 0:
		add("rootkeys: none of the configured keys is a usable root trust anchor")
	}

	for _, out := range []struct {
		key    string
		values []string
		want4  bool
	}{
		{"outboundips", c.OutboundIPs, true},
		{"outboundip6s", c.OutboundIP6s, false},
	} {
		// Read only behind ipv6access, so on a host without v6 the whole
		// list has no effect — not just the locality of its entries.
		if !out.want4 && !c.IPv6Access {
			continue
		}
		for _, addr := range out.values {
			ip := net.ParseIP(addr)
			if ip == nil {
				add("%s %q: must be an IP address", out.key, addr)
				continue
			}
			// Putting a v6 address in the v4 list is a mistake the resolver
			// cannot act on, and nothing downstream says so.
			if is4 := ip.To4() != nil; is4 != out.want4 {
				family := "IPv6"
				if out.want4 {
					family = "IPv4"
				}
				add("%s %q: must be an %s address", out.key, addr, family)
				continue
			}
			// The resolver binds its outbound sockets to these, and stops
			// the process outright when one is not an address this machine
			// holds — after this test has already reported success.
			if !localAddress(ip) {
				add("%s %q: is not an address of this machine", out.key, addr)
			}
		}
	}

	if c.API != "" {
		host, port, err := net.SplitHostPort(c.API)
		switch {
		case err != nil || port == "":
			add("api = %q: must be host:port", c.API)
		default:
			_ = host
			if _, err := usablePort(port, "tcp"); err != nil {
				add("api = %q: %v", c.API, err)
			}
		}
	}

	// Both are created when absent, so only a plain file already sitting at
	// the path is a problem — the Mkdir that follows would fail on it.
	// An empty path is left alone. Load fails loudly on os.Mkdir("") a few
	// lines further on, and Validate is also called on configurations built
	// in code, which have no working directory to speak of — requiring one
	// here would refuse every such caller to co-report a failure that is
	// already impossible to miss.
	// The working directory is written for certain — the trust-anchor store
	// lives there — so it has to take an entry.
	pending := c.Directory
	if c.Directory != "" {
		if err := writableDir(c.Directory, ""); err != nil {
			add("directory = %q: %v", c.Directory, err)
		}
	}

	// An empty blocklistdir is the normal case, not an unset one: the
	// middleware fills it in under the working directory, and a plain file
	// or an unwritable directory there leaves both the downloaded and the
	// local lists quietly unloaded.
	//
	// Only what is already at the derived path can be judged, though. Load
	// creates the working directory after this gate, so on a fresh install
	// the parent of the default is legitimately not there yet — asking for
	// it would refuse every first run. A blocklistdir the operator wrote
	// themselves is nobody's to create, so that one is asked in full.
	//
	// Write is not required of it, unlike the working directory. The
	// middleware reads local lists from there and only logs when it cannot
	// download into it, so a read-only mount carrying nothing but local
	// lists is a working setup — and refusing it would stop a server that
	// runs today.
	//
	// Whether it has to be written depends on what is being loaded into it:
	// a remote list is downloaded into the directory with os.Create, so with
	// one configured a read-only mount loads nothing at all.
	dirCheck := usableDir
	if len(c.BlockLists) > 0 {
		dirCheck = writableDir
	}

	switch {
	case c.BlockListDir != "":
		if err := dirCheck(c.BlockListDir, pending); err != nil {
			add("blocklistdir = %q: %v", c.BlockListDir, err)
		}
	case c.Directory != "":
		derived := filepath.Join(c.Directory, "blacklists")
		if _, err := os.Lstat(derived); err == nil {
			if err := dirCheck(derived, ""); err != nil {
				add("blocklistdir defaults to %q: %v", derived, err)
			}
		}
	}

	// Opened with O_CREATE, so it need not exist; a directory at the path
	// makes that open fail and takes the server down at startup.
	// Opened write-only with O_CREATE. The middleware logs a failure there and
	// carries on with access logging quietly switched off, so every way of
	// getting this wrong is silent.
	if c.AccessLog != "" {
		// Stat, not Lstat: OpenFile follows a symlink, so a link to a
		// writable file is usable and rejecting it would refuse a setup that
		// works today.
		info, err := os.Stat(c.AccessLog)
		switch {
		case os.IsNotExist(err):
			// Created on open, but only inside a directory already there —
			// and for a symlink that is the target's directory, not the
			// link's, since the open follows the link before creating.
			target := accessLogTarget(c.AccessLog)

			// A trailing separator says the path is a directory, and the
			// open refuses it outright. Unlike a directory setting, where
			// the separator means nothing and is cleaned away, here it
			// changes what the name asks for — so it is reported as the
			// wrong kind of name rather than as a missing parent.
			if endsInSeparator(c.AccessLog) || endsInSeparator(target) {
				add("accesslog = %q: names a directory, want a file", c.AccessLog)
				break
			}
			if err := existingDir(literalParent(target), pending); err != nil {
				add("accesslog = %q: %v", c.AccessLog, err)
			}
		case err != nil:
			add("accesslog = %q: %v", c.AccessLog, err)
		case info.IsDir():
			add("accesslog = %q: is a directory, want a file", c.AccessLog)
		case info.Mode()&os.ModeNamedPipe != 0:
			// Left alone on purpose. Opening a pipe to see whether it can be
			// opened is not a free question: a reader waiting on it — cat, a
			// log collector, the container runtime behind /dev/stdout — sees
			// EOF the moment the last writer closes, and a probe that opens
			// and closes is exactly that. The reader exits, and the open the
			// middleware makes a moment later then waits forever for it.
			//
			// So this check would cause the hang it was looking for. Whether
			// a reader is attached is a fact about the running system, not
			// about the file, and it belongs to the runtime the same way
			// whether an upstream answers does.

		default:
			// Judged by opening it, not by its type: a character device is
			// the usual container spelling — /dev/null, or /dev/stdout when
			// the output is a file — and os.OpenFile takes it.
			if err := openable(c.AccessLog, os.O_WRONLY); err != nil {
				add("accesslog = %q: %v", c.AccessLog, err)
			}
		}
	}

	// Demo seeds the registry and switches the middleware on just as Enabled
	// does, so both open the same settings.
	if c.Kubernetes.Enabled || c.Kubernetes.Demo {
		if c.Kubernetes.Enabled && c.Kubernetes.Kubeconfig != "" {
			if err := regularFile(c.Kubernetes.Kubeconfig); err != nil {
				add("kubernetes.kubeconfig = %q: %v", c.Kubernetes.Kubeconfig, err)
			}
		}
		// Lowercased and stripped of a trailing dot, then used as the suffix
		// every lookup is matched against. A name that cannot be one matches
		// nothing, and the middleware answers for no query at all.
		//
		// The runtime strips one trailing dot and then puts one back, so
		// "cluster.local.." becomes a suffix with a doubled dot that no
		// query can match. Judging the value after the same single strip
		// would let that through, so the raw value is judged instead.
		if raw := strings.ToLower(c.Kubernetes.ClusterDomain); raw != "" {
			if !validDomainName(strings.TrimSuffix(raw, ".")) || strings.HasSuffix(raw, "..") {
				add("kubernetes.cluster_domain = %q: is not a valid domain name", c.Kubernetes.ClusterDomain)
			}
		}
	}

	if c.HostsFile != "" {
		if err := regularFile(c.HostsFile); err != nil {
			add("hostsfile = %q: %v", c.HostsFile, err)
		}
	}

	// Only read when the feature is on, so a stale source left behind by an
	// operator who turned hyperlocal off does not stop the server.
	sources := c.HyperlocalRootSources
	if !c.HyperlocalRoot {
		sources = nil
	}
	for _, raw := range sources {
		// The manager trims each source and drops the ones left empty,
		// falling back to its built-in list, so neither surrounding space
		// nor a blank entry is a problem to report.
		addr := strings.TrimSpace(raw)
		if addr == "" {
			continue
		}
		// Hostnames are expected here: the built-in sources are the root
		// servers' names.
		host, port, err := net.SplitHostPort(addr)
		switch {
		case err != nil || host == "" || port == "":
			add("hyperlocal_root_sources %q: must be host:port", raw)
		default:
			if n, err := usablePort(port, "tcp"); err != nil || n == 0 {
				add("hyperlocal_root_sources %q: must have a port to reach", raw)
			}
		}
	}

	// The cache refuses anything above 90 and then disables prefetch
	// entirely, so 91-100 passed this test and silently turned the feature
	// off. The low end is clamped up to 10 rather than refused.
	// Negatives here are settled away rather than refused: a negative
	// minimization count folds to zero, which turns minimization off, and a
	// negative one-label count falls back to the default. Both leave the
	// server running something the file does not say.
	if c.QnameMaxMinimizeCount != nil && *c.QnameMaxMinimizeCount < 0 {
		add("qname_max_minimize_count = %d: must not be negative (0 turns minimization off)", *c.QnameMaxMinimizeCount)
	}
	// Only when it is the value actually read: with the new key set, the
	// deprecated one is never consulted, so judging it would refuse a config
	// whose live setting is fine.
	if c.QnameMaxMinimizeCount == nil && c.QnameMinLevel < 0 {
		add("qname_min_level = %d: must not be negative", c.QnameMinLevel)
	}
	// One label at a time is only meaningful while minimization is on, and
	// the runtime settles the pair together: a count above the maximum is
	// quietly lowered to it, and with minimization off the field is not read
	// at all. Judging the fields separately reported a value that has no
	// effect and missed one that is silently changed.
	if maxCount, _ := c.QnameMinimizeParams(); maxCount > 0 {
		switch {
		case c.QnameMinimizeOneLabel < 0:
			add("qname_minimize_one_label = %d: must not be negative", c.QnameMinimizeOneLabel)
		case c.QnameMinimizeOneLabel > maxCount:
			add("qname_minimize_one_label = %d: must not exceed qname_max_minimize_count (%d), which is what it is lowered to",
				c.QnameMinimizeOneLabel, maxCount)
		}
	}

	// The cache raises anything under 1024 to 1024 without saying so, so a
	// file naming a smaller cache does not describe the server that runs.
	// Zero still means "use the default".
	if c.CacheSize > 0 && c.CacheSize < 1024 {
		add("cachesize = %d: must be 0 (default) or at least 1024", c.CacheSize)
	}

	// A percentage of the original TTL, and the cache moves anything outside
	// 10..90 without saying so: above 90 it turns prefetch off entirely, and
	// 1..9 it raises to 10. Zero is the documented way to disable it.
	if c.Prefetch > 90 || (c.Prefetch > 0 && c.Prefetch < 10) {
		add("prefetch = %d: is a percentage of the original TTL and must be 0 (off) or between 10 and 90", c.Prefetch)
	}

	// Only when the feature is on: reflex.New returns before reading the
	// threshold otherwise, so a stale value under a disabled feature has no
	// effect and must not stop the server.
	//
	// NaN is called out separately because it slips through a range test —
	// every comparison against it is false, including the ones the middleware
	// itself makes, so it lands on the same silent default as an out-of-range
	// value.
	if c.ReflexEnabled {
		switch {
		case math.IsNaN(float64(c.ReflexThreshold)):
			add("reflexthreshold is not a number; must be between 0 and 1")
		case c.ReflexThreshold != 0 && (c.ReflexThreshold < 0 || c.ReflexThreshold > 1):
			// Out of range is silently replaced by the default, so an operator
			// who wrote 42 believes they set a threshold they did not.
			add("reflexthreshold = %v: must be between 0 and 1", c.ReflexThreshold)
		}
	}

	for name, plugin := range c.Plugins {
		if plugin.Path == "" {
			add("plugin %q has no path", name)
			continue
		}
		if err := regularFile(plugin.Path); err != nil {
			add("plugin %q path %q: %v", name, plugin.Path, err)
		}
	}
}

// validateNameLists covers the settings that name zones or hosts.
func (c *Config) validateNameLists(add func(string, ...any)) {
	for _, list := range []struct {
		key      string
		values   []string
		wildcard bool
	}{
		// Only the blocklist reads the star: set() strips "*." and files the
		// rest as a wildcard block. The whitelist is stored verbatim and
		// matched up the hierarchy, so "*.example.com" there becomes a key
		// with a literal star label that no query ever produces — and the
		// operator who wrote it, meaning to exempt the subdomains, gets
		// nothing. Whitelisting "example.com" already covers them.
		{"blocklist", c.Blocklist, true},
		{"whitelist", c.Whitelist, false},
		{"emptyzones", c.EmptyZones, false},
	} {
		for _, entry := range list.values {
			name := entry
			if list.wildcard {
				name = strings.TrimPrefix(name, "*.")
			} else if strings.HasPrefix(name, "*.") {
				add("%s %q: the leading \"*.\" is blocklist syntax and is not read here; write the name itself, which already covers its subdomains", list.key, entry)
				continue
			}
			if name == "" {
				add("%s entry %q is empty", list.key, entry)
				continue
			}
			if _, ok := dns.IsDomainName(name); !ok {
				add("%s %q: not a valid domain name", list.key, entry)
				continue
			}
			// An empty zone outside the locally-served tree is dropped, and
			// a list where every entry is dropped falls back to all of them
			// — so the operator gets the opposite of a narrowed list.
			if list.key == "emptyzones" && !emptyzones.Covers(name) {
				add("emptyzones %q: is not one of the locally-served zones (RFC 6303), so it is dropped", entry)
			}
		}
	}

	for _, u := range c.BlockLists {
		parsed, err := url.Parse(u)
		switch {
		// Hostname, not Host: "http://:80/list" has the latter and nothing
		// to connect to.
		case err != nil || parsed.Hostname() == "":
			add("blocklists %q: must be an http:// or https:// URL", u)
		case parsed.Scheme != "http" && parsed.Scheme != "https":
			// The updater fetches with an http.Client, so any other scheme
			// fails on an unsupported protocol and the list never loads.
			add("blocklists %q: scheme %q cannot be fetched; use http or https", u, parsed.Scheme)
		default:
			// An explicit port is dialled like any other; out of range or
			// zero fails at connect and the list simply never loads.
			if port := parsed.Port(); port != "" {
				if n, err := usablePort(port, "tcp"); err != nil || n == 0 {
					add("blocklists %q: port %q has nothing to connect to", u, port)
				}
			}
		}
	}
}

// validateSubTables covers the settings that live under their own headings.
func (c *Config) validateSubTables(add func(string, ...any)) {
	for i := range c.Views {
		view := &c.Views[i]
		label := view.Zone
		if label == "" {
			label = fmt.Sprintf("#%d", i+1)
		}
		// zone is a free-form label. The middleware only carries it into log
		// lines; matching is done by the networks and the answers' own owner
		// names. Validating it as a domain would reject descriptive labels
		// that work today and stop the server on upgrade.
		for _, network := range view.Networks {
			if !validCIDR(network) {
				add("view %s network %q: must be a CIDR block", label, network)
			}
		}
		for _, answer := range view.Answers {
			// NewRR reports no error for a line that holds no record —
			// blank, a comment, a directive — and hands back nothing. The
			// view then answers with one entry fewer than the file lists,
			// or with none at all.
			rr, err := dns.NewRR(answer)
			switch {
			case err != nil:
				add("view %s answer %q: %v", label, answer, err)
			case rr == nil:
				add("view %s answer %q: is not a record, so the view would not serve it", label, answer)
			}
		}
	}

	// These are the rules middleware/dns64 applies at startup. A prefix that
	// only looks like IPv6 is dropped there, and if it was the only one the
	// resolver falls back to 64:ff9b::/96 — so a config test that accepted
	// it would report success while traffic went to a different NAT64
	// prefix than the file names.
	//
	// The family test is the mask length, not To4(): an IPv4-mapped range
	// like ::ffff:0:0/96 has a non-nil To4() and is a legal Pref64 input.
	//
	// dns64 reads every one of its lists through TrimSpace, so surrounding
	// space is not a problem there and rejecting it would refuse a config the
	// server runs today. The ecs list below is parsed raw, so it is not
	// trimmed here either — each list is judged the way its own reader reads
	// it.
	//
	// All of it is gated on enabled, because both constructors return before
	// reading another field when the feature is off. A config that has run
	// for years with a stale value under a disabled section must keep
	// starting; refusing it would turn an upgrade into an outage over a
	// setting that has no effect either way.
	c.validateDNS64(add)
	c.validateECS(add)
}

func (c *Config) validateDNS64(add func(string, ...any)) {
	if !c.DNS64.Enabled {
		return
	}

	validPrefixBits := map[int]bool{32: true, 40: true, 48: true, 56: true, 64: true, 96: true}
	// Whether the prefix set the runtime ends up with contains the well-known
	// one, which is what decides if exclude_a_networks is read at all.
	wellKnown, usablePrefixes := false, 0
	for _, raw := range c.DNS64.Prefixes {
		prefix := strings.TrimSpace(raw)
		_, network, err := net.ParseCIDR(prefix)
		if err != nil {
			add("dns64 prefix %q: must be a CIDR block", raw)
			continue
		}
		if len(network.Mask) != net.IPv6len {
			add("dns64 prefix %q: is IPv4, want IPv6", prefix)
			continue
		}
		bits, _ := network.Mask.Size()
		if !validPrefixBits[bits] {
			add("dns64 prefix %q: length /%d invalid; must be /32, /40, /48, /56, /64, or /96", prefix, bits)
			continue
		}
		// RFC 6052 §2.2 reserves byte 8; at /96 the operator's prefix
		// already covers it.
		if bits == 96 && len(network.IP) >= 9 && network.IP[8] != 0 {
			add("dns64 prefix %q: byte 8 must be zero (RFC 6052 section 2.2 reserved)", prefix)
			continue
		}
		usablePrefixes++
		if network.String() == wellKnownPrefix {
			wellKnown = true
		}
	}
	// With no usable prefix the runtime falls back to the well-known one, so
	// the exclude list is read either way.
	if usablePrefixes == 0 {
		wellKnown = true
	}
	// The exclude lists are family-specific at runtime and the wrong family
	// is dropped with a log line nobody reads, so the exclusion the operator
	// wrote silently does not apply. Family is decided by mask length, not
	// To4(): ParseCIDR returns a 4-byte mask for IPv4 and 16 for IPv6, and
	// an IPv4-mapped IPv6 range would fool the address test.
	// Only consulted under the well-known prefix (RFC 6147 section 5.1.4):
	// with a custom prefix the runtime skips the parse entirely, so a stale
	// entry here has no effect and must not stop the server.
	excludeA := c.DNS64.ExcludeANetworks
	if !wellKnown {
		excludeA = nil
	}

	for _, list := range []struct {
		key    string
		values []string
		mask   int // 0 for either family
	}{
		{"dns64 client_networks", c.DNS64.ClientNetworks, 0},
		{"dns64 exclude_a_networks", excludeA, net.IPv4len},
		{"dns64 exclude_aaaa_networks", c.DNS64.ExcludeAAAANetworks, net.IPv6len},
	} {
		for _, raw := range list.values {
			// Every dns64 list is read through TrimSpace.
			_, parsed, err := net.ParseCIDR(strings.TrimSpace(raw))
			if err != nil {
				add("%s %q: must be a CIDR block", list.key, raw)
				continue
			}
			if list.mask != 0 && len(parsed.Mask) != list.mask {
				family := "IPv4"
				if list.mask == net.IPv6len {
					family = "IPv6"
				}
				add("%s %q: must be %s", list.key, raw, family)
			}
		}
	}
	for _, raw := range c.DNS64.ExcludeZones {
		// Trimmed, lowercased, and given a trailing dot before use, and a
		// blank entry is skipped — so none of those is worth reporting.
		zone := strings.TrimSpace(strings.ToLower(raw))
		if zone == "" {
			continue
		}
		if _, ok := dns.IsDomainName(zone); !ok {
			add("dns64 exclude_zones %q: not a valid domain name", raw)
		}
	}
}

// wellKnownPrefix is the NAT64 prefix from RFC 6052 section 2.1, in the
// canonical spelling net.IPNet.String produces.
const wellKnownPrefix = "64:ff9b::/96"

func (c *Config) validateECS(add func(string, ...any)) {
	if !c.ECS.Enabled {
		return
	}

	// internal/ecs hands each entry straight to netip.ParsePrefix, so unlike
	// the dns64 lists above this one is judged exactly as written.
	for _, network := range c.ECS.ClientNetworks {
		if !validCIDR(network) {
			add("ecs client_networks %q: must be a CIDR block", network)
		}
	}

	for _, bits := range []struct {
		key   string
		value uint8
		max   uint8
	}{
		{"ecs forward_v4", c.ECS.ForwardV4Max, 32},
		{"ecs min_scope_v4", c.ECS.MinScopeV4, 32},
		{"ecs forward_v6", c.ECS.ForwardV6Max, 128},
		{"ecs min_scope_v6", c.ECS.MinScopeV6, 128},
	} {
		if bits.value > bits.max {
			add("%s = %d: must not exceed %d", bits.key, bits.value, bits.max)
		}
	}

	if c.ECS.CacheLimitTTL.Duration < 0 {
		add("ecs.cache_limit_ttl = %q: must not be negative", c.ECS.CacheLimitTTL.Duration)
	}
}

// dnsKeyFlagRevoke is the REVOKE bit of RFC 5011 section 2.1.
const dnsKeyFlagRevoke = 0x0080

// forwardsRoot reports whether a forward zone takes every query. Matching is
// the same test ForwardZoneFor makes — a canonical apex of "." covers every
// name, and a zone with no servers is skipped there — so a name this says is
// the root is one the handler will actually forward on.
func (c *Config) forwardsRoot() bool {
	for i := range c.ForwardZones {
		zone := &c.ForwardZones[i]
		if len(zone.Servers) > 0 && dns.CanonicalName(zone.Name) == "." {
			return true
		}
	}
	return false
}

// localAddress reports whether ip is one this machine holds. The resolver
// makes the same test before binding an outbound socket to it and stops the
// process when it fails, so a config test that skipped it would report success
// on a file the server refuses.
func localAddress(ip net.IP) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		// Nothing to compare against; leave the judgement to the runtime
		// rather than invent a failure.
		return true
	}
	for _, a := range addrs {
		switch v := a.(type) {
		case *net.IPNet:
			if v.IP.Equal(ip) {
				return true
			}
		case *net.IPAddr:
			if v.IP.Equal(ip) {
				return true
			}
		}
	}
	return false
}

// validCIDR reports whether a prefix is one the access list, the views and
// the ECS policy will take. All three reach netip.ParsePrefix — the first two
// through internal/ipset — and it is stricter than net.ParseCIDR about the
// bits after the slash: "10.0.0.0/08" parses there and not here, so accepting
// it would pass a file whose only access-list entry is then dropped, leaving
// an empty allow set that blocks every client.
//
// dns64 is not one of these callers. It parses with net.ParseCIDR and takes
// the leading zero, so its lists are judged with that instead.
func validCIDR(s string) bool {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return false
	}
	// A prefix that stays inside the IPv4-mapped range once masked is filed
	// under IPv6 by internal/ipset, while a client arriving over IPv4 is
	// unmapped and looked up under IPv4 — so the entry sits in a table
	// nothing searches. ECS compares prefix to address directly, where the
	// families disagree just as flatly. Either way it matches nobody, and as
	// the only access-list entry it would leave an empty allow set. The
	// operator wants the plain form: 192.0.2.0/24.
	//
	// Masked, not as written: "::ffff:192.0.2.0/64" covers ::/64, which real
	// IPv6 clients fall inside. Only /96 and narrower stay mapped, and only
	// those are dead.
	return !p.Masked().Addr().Is4In6()
}

// regularFile reports whether path is something the server can open and read.
// Existence alone is not enough: a directory satisfies Stat and then fails at
// the read, which for a certificate and key means the TLS listener stops
// startup after this test has already reported success.
func regularFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("is a directory, want a file")
	}
	// Not merely "not a directory": a FIFO passes that test and then blocks
	// the reader, and a socket or device node fails it in its own way. Mode
	// is checked rather than the file being opened, because a config test
	// run by a different user than the service would read permissions that
	// are not the ones that matter.
	if !info.Mode().IsRegular() {
		return fmt.Errorf("is a %s, want a regular file", fileKind(info.Mode()))
	}
	// Type alone does not make it readable, and every consumer here opens the
	// file: a certificate, a hosts file and a plugin all fail later on a mode
	// this test would have passed. Startup runs under the same identity, so
	// the open answers the question that matters.
	return openable(path, os.O_RDONLY)
}

// openFile is os.OpenFile, as a variable so a test can record which paths this
// package opens. What it does not open matters as much as what it does: a pipe
// is left untouched, and only a recording of the calls can pin that.
var openFile = os.OpenFile

// openable reports whether path can be opened with the given flags, without
// creating or truncating anything.
func openable(path string, flag int) error {
	// The path is the operator's own config value, opened to answer whether
	// the server will be able to use it — and opened so that it never waits.
	// Pipes do not reach here, but a character device can hold an open too:
	// a serial line waits for carrier.
	f, err := openFile(path, flag|nonBlockingOpen, 0) //nolint:gosec // G304 - the path under test is the input
	if err != nil {
		return err
	}
	return f.Close()
}

func fileKind(mode os.FileMode) string {
	switch {
	case mode&os.ModeNamedPipe != 0:
		return "named pipe"
	case mode&os.ModeSocket != 0:
		return "socket"
	case mode&os.ModeDevice != 0:
		return "device"
	case mode&os.ModeSymlink != 0:
		return "symlink"
	}
	return "special file"
}

// writableDir reports whether path can serve as a directory the server writes
// into. Absence is fine — both callers create it — but a plain file sitting at
// the path is not, because the Mkdir that would follow fails.
// pending is the working directory Load creates just after the gate. A parent
// that is exactly it is treated as present: the server makes it, and then
// makes what goes inside. Only that one level, because Load uses Mkdir.
// usableDir is writableDir without asking whether an entry can be made in it.
func usableDir(path, pending string) error {
	return dirCheck(path, pending, false)
}

func writableDir(path, pending string) error {
	return dirCheck(path, pending, true)
}

func dirCheck(path, pending string, mustWrite bool) error {
	// Lstat, so a symlink is judged as itself: a dangling one looks absent to
	// Stat, and then Mkdir fails on it with EEXIST because the entry is
	// already there.
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		// Created with Mkdir, not MkdirAll, so one missing level is made and
		// two are not — and Mkdir resolves every component on the way, so a
		// "missing/../db" fails on the middle one however it cleans up.
		return existingDir(literalParent(path), pending)
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		// A symlink that resolves to a directory is usable; one that does
		// not is the case Mkdir cannot get past.
		target, terr := os.Stat(path)
		if terr != nil {
			return fmt.Errorf("is a symlink that does not resolve: %w", terr)
		}
		if !target.IsDir() {
			return fmt.Errorf("is a symlink to a file, want a directory")
		}
		// Through the link, because that is the path the server writes to.
		// Returning here without asking accepted a symlink to a directory
		// that the same check refuses when it is named directly.
		if !mustWrite {
			return readable(path)
		}
		return creatable(path)
	}
	if !info.IsDir() {
		return fmt.Errorf("is a file, want a directory")
	}
	if !mustWrite {
		return readable(path)
	}
	return creatable(path)
}

// readable reports whether this process can list dir. Stat says nothing about
// that — a directory with no permission bits at all satisfies it — while the
// blocklist middleware walks the directory and, when it cannot, logs once and
// loads no local list at all.
func readable(dir string) error {
	f, err := openFile(dir, os.O_RDONLY, 0) //nolint:gosec // G304 - the path under test is the input
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck // nothing was written

	entries, err := f.ReadDir(1)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if len(entries) == 0 {
		// Nothing to walk into, which is a fine state for a list directory.
		return nil
	}

	// Listing is not walking. A directory carrying read but not execute
	// hands back its entry names and then refuses to stat any of them —
	// which is exactly where the middleware's walk stops, loading nothing.
	if _, err := os.Lstat(filepath.Join(dir, entries[0].Name())); err != nil {
		return err
	}
	return nil
}

// samePath reports whether two spellings name the same place.
//
// Cleaning answers that on Windows, which collapses ".." itself. Where the
// components are walked instead, a ".." only resolves once what comes before
// it exists — so "missing/../db" is not the directory the server is about to
// create, however it cleans up, and the two are compared as written.
func samePath(a, b string) bool {
	// Made absolute first, because a relative spelling resolves against the
	// working directory of the process: nothing chdirs, so "db" and
	// "<cwd>/db" are one place and were being called two.
	a, b = absKeepingComponents(a), absKeepingComponents(b)

	// Where the part before the last element is there, the system resolves
	// it — through symlinks, through ".." — and so does this. It is what
	// makes "/var/db" and "/private/var/db" one place on a Mac, and
	// "there/../db" and "db" one place anywhere.
	if ra, ok := resolveParent(a); ok {
		if rb, ok := resolveParent(b); ok {
			return equalPaths(ra, rb)
		}
	}

	// Nothing to resolve against, so the spellings answer for themselves.
	// Cleaning is right where the system cleans; where components are
	// walked, a ".." among them has not resolved yet and the two are only
	// the same if they are written the same.
	if cleansPathComponents || (!hasDotDot(a) && !hasDotDot(b)) {
		return equalPaths(filepath.Clean(a), filepath.Clean(b))
	}
	return equalPaths(trimTrailingSeparators(a), trimTrailingSeparators(b))
}

// resolveParent rewrites path with everything before its last element
// resolved through the filesystem, and reports whether that part exists. The
// last element is left alone: it is the one that may not be there yet.
func resolveParent(path string) (string, bool) {
	trimmed := trimTrailingSeparators(path)
	parent := literalParent(trimmed)

	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", false
	}
	return filepath.Join(resolved, filepath.Base(trimmed)), true
}

// absKeepingComponents resolves a relative path against the working directory
// without cleaning it. filepath.Abs cleans, and that would drop the ".."
// components the comparison below still has to see.
func absKeepingComponents(path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	cwd, err := os.Getwd()
	if err != nil {
		return path
	}
	return joinKeepingComponents(cwd, path)
}

// equalPaths compares two already-normalised paths the way the filesystem
// does. Windows does not distinguish case, so neither does this there.
func equalPaths(a, b string) bool {
	if cleansPathComponents {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// trimTrailingSeparators drops the separators at the end of path, keeping a
// lone root as itself.
func trimTrailingSeparators(path string) string {
	i := len(path)
	for i > 1 && os.IsPathSeparator(path[i-1]) {
		i--
	}
	return path[:i]
}

// hasDotDot reports whether path has a ".." among its components. Bytes, not
// runes: separators are ASCII, and narrowing a multi-byte rune to a byte can
// land on one by accident.
func hasDotDot(path string) bool {
	start := 0
	for i := 0; i <= len(path); i++ {
		if i < len(path) && !os.IsPathSeparator(path[i]) {
			continue
		}
		if path[start:i] == ".." {
			return true
		}
		start = i + 1
	}
	return false
}

// existingDir reports whether path is a directory that is already there and
// can be written into.
func existingDir(path, pending string) error {
	if pending != "" && samePath(path, pending) {
		// Not there yet, and about to be. Everything under it is created
		// after that, in the order the server does it.
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return nil
		}
	}

	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("parent directory %q: %w", path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("parent %q is a file, want a directory", path)
	}
	if err := creatable(path); err != nil {
		return fmt.Errorf("parent directory %q: %w", path, err)
	}
	return nil
}

// cleansPathComponents is whether the system collapses ".." itself before it
// touches the filesystem. Windows does; unix resolves a path one component at
// a time.
//
// It is a variable rather than a check at each site so a test on either
// platform can exercise both rules — this file has been wrong about the one
// it does not run twice, and only Windows CI noticed. Which rule is the
// default here cannot be tested locally, since any assertion would compare
// this expression against itself; that half stays CI's job.
var cleansPathComponents = runtime.GOOS == "windows"

// literalParent returns everything before the last element of path.
//
// Which parent that is depends on how the system resolves a path. Unix walks
// it one component at a time, so "missing/../access.log" fails on the
// "missing" that is not there and the parent has to keep the components as
// written — filepath.Dir cleans, and would answer "." for a path nothing can
// open. Windows collapses ".." itself before touching the filesystem, so
// there the cleaned parent is the one that decides, and keeping the
// components would refuse a path the OS is perfectly happy with.
//
// Trailing separators are dropped either way, so a path written as a
// directory yields its own parent rather than itself.
func literalParent(path string) string {
	if cleansPathComponents {
		return filepath.Dir(filepath.Clean(path))
	}

	i := len(path)
	for i > 0 && os.IsPathSeparator(path[i-1]) {
		i--
	}
	for i > 0 && !os.IsPathSeparator(path[i-1]) {
		i--
	}
	for i > 1 && os.IsPathSeparator(path[i-1]) {
		i--
	}
	if i == 0 {
		return "."
	}
	return path[:i]
}

// endsInSeparator reports whether path is written as a directory. Both
// spellings are checked because a config carried between platforms may use
// either, and the open rejects the name on both.
func endsInSeparator(path string) bool {
	return strings.HasSuffix(path, "/") || strings.HasSuffix(path, string(os.PathSeparator))
}

// accessLogTarget resolves the symlink chain the open would follow, so a link
// is judged where the file would actually be made. Stat reports a dangling
// link as absent, which read as an ordinary missing file and had the link's
// own directory checked instead of the target's.
//
// The bound is above what any system will follow — Linux gives up at forty,
// this machine at around thirty — so a chain that reaches it is one the stat
// above has already refused with ELOOP. It is here to end the loop on a link
// that points at itself, not to judge length.
func accessLogTarget(path string) string {
	const maxHops = 64

	for range maxHops {
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink == 0 {
			return path
		}
		link, err := os.Readlink(path)
		if err != nil {
			return path
		}
		if filepath.IsAbs(link) {
			path = link
			continue
		}
		path = joinKeepingComponents(literalParent(path), link)
	}
	return path
}

// joinKeepingComponents puts a relative symlink target under the directory
// holding the link.
//
// filepath.Join cleans, and on a system that resolves a path one component at
// a time that loses the answer: a target of "missing/../real.log" becomes
// "real.log" and looks like it lives somewhere that exists, while the open
// follows the target as written and fails on the "missing" that is not there.
// Windows collapses ".." itself, so cleaning is what it does and Join is
// right there.
func joinKeepingComponents(dir, target string) string {
	if cleansPathComponents {
		joined := filepath.Join(dir, target)
		// Join cleans, and that takes the trailing separator with it — the
		// one thing that says the target names a directory, which the open
		// refuses. The unix branch below keeps it by not cleaning at all, so
		// this is the only place it has to be put back, and Windows CI is
		// the only thing that exercises it.
		if endsInSeparator(target) && !endsInSeparator(joined) {
			joined += string(os.PathSeparator)
		}
		return joined
	}
	if dir == "" {
		return target
	}
	if os.IsPathSeparator(dir[len(dir)-1]) {
		return dir + target
	}
	return dir + string(os.PathSeparator) + target
}

// creatable reports whether this process can make an entry in dir. Mode bits
// alone do not answer it — ownership, group membership and the mount's own
// flags all decide — so the question is put the only portable way there is,
// by creating something and taking it straight back out. The server creates
// its working directory here anyway, and a check that skipped this passed a
// read-only parent whose failure surfaces one run later for the working
// directory, and not at all for the access log.
func creatable(dir string) error {
	f, err := os.CreateTemp(dir, ".sdns-config-test-*")
	if err != nil {
		return err
	}
	// Set up straight after creating it, so no later failure can leave the
	// probe behind. Neither result changes the answer: the directory took an
	// entry, which is the whole question.
	name := f.Name()
	defer func() {
		_ = f.Close()
		_ = os.Remove(name)
	}()
	return nil
}

// anchorKeyProblem reports why this key cannot be verified with, or nil when
// it can. Both the set of usable algorithms and the shape each one demands of
// its public key belong to the DNSSEC library, so the library is asked rather
// than kept in step with by hand: a list written here would claim ED448 works,
// and it does not.
//
// A signature this throwaway fails for many reasons, and only these two are
// about the key. Every other outcome — a crypto mismatch, a bad signature —
// means the algorithm was recognised and the key parsed, which is all that is
// being asked. Real keys of every supported algorithm reach those outcomes.
func anchorKeyProblem(key *dns.DNSKEY) error {
	probe := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: key.Hdr.Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET},
		TypeCovered: dns.TypeDNSKEY,
		Algorithm:   key.Algorithm,
		OrigTtl:     key.Hdr.Ttl,
		KeyTag:      key.KeyTag(),
		SignerName:  key.Hdr.Name,
		Signature:   "AA==",
	}

	err := probe.Verify(key, []dns.RR{key})
	name := dns.AlgorithmToString[key.Algorithm]
	switch {
	case errors.Is(err, dns.ErrAlg):
		return fmt.Errorf("algorithm %d (%s) cannot be verified with", key.Algorithm, name)
	case err == nil, errors.Is(err, expectedProbeFailure(key.Algorithm)):
		// The key was loaded and used, and only the throwaway signature was
		// rejected — which is all this is asking.
	default:
		// Anything else means the key itself stopped the verifier. Listing
		// the failures to reject would miss the ones the crypto packages add
		// over time: Go now refuses an RSA key under 1024 bits with a policy
		// error that is neither a parse failure nor a signature mismatch, and
		// an anchor like that fails every real verification the same way.
		return fmt.Errorf("public key is not usable for algorithm %d (%s): %v", key.Algorithm, name, err)
	}

	// The probe cannot see this on its own. A throwaway signature decodes to
	// r = s = 0, and ecdsa.Verify rejects that before it ever looks at the
	// public point — so a curve key of the right length that is not a point
	// on the curve comes back as a bad signature and looks usable.
	if key.Algorithm == dns.ED25519 {
		if err := ed25519Usable(key.PublicKey); err != nil {
			return fmt.Errorf("public key is not usable for algorithm %d (%s): %v", key.Algorithm, name, err)
		}
	}

	if curve := ecdhCurve(key.Algorithm); curve != nil {
		raw, decodeErr := base64.StdEncoding.DecodeString(key.PublicKey)
		if decodeErr != nil {
			return fmt.Errorf("public key is not base64: %v", decodeErr)
		}
		// DNSKEY carries the coordinates bare (RFC 6605 section 4); the
		// 0x04 tag is what NewPublicKey expects on an uncompressed point.
		if _, err := curve.NewPublicKey(append([]byte{4}, raw...)); err != nil {
			return fmt.Errorf("public key is not usable for algorithm %d (%s): %v", key.Algorithm, name, err)
		}
	}
	return nil
}

// expectedProbeFailure is the one error a usable key of this algorithm may
// produce against a signature that is deliberately wrong. Naming what success
// looks like rather than enumerating failures keeps a key the crypto packages
// reject for a new reason from passing as usable.
func expectedProbeFailure(alg uint8) error {
	switch alg {
	case dns.RSAMD5, dns.RSASHA1, dns.RSASHA1NSEC3SHA1, dns.RSASHA256, dns.RSASHA512:
		return rsa.ErrVerification
	}
	// ECDSA and the Edwards curves fail a bad signature inside miekg itself.
	return dns.ErrSig
}

// ed25519 probe inputs. The signature is deliberately wrong, so the only
// question the verifier can answer is whether the key itself is usable.
var (
	ed25519ProbeMessage = []byte("sdns config test")
	ed25519ProbeOptions = &ed25519.Options{Hash: crypto.Hash(0)}
)

// ed25519BadSignature is what VerifyWithOptions reports when the key is fine
// and only the signature is wrong. It is measured from a key generated here
// rather than written out as a string, so if a future Go release rewords it
// both sides move together — a hardcoded message would turn this check too
// strict, which is the failure worth avoiding.
var ed25519BadSignature = sync.OnceValue(func() string {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		return ""
	}
	e := ed25519.VerifyWithOptions(pub, ed25519ProbeMessage,
		make([]byte, ed25519.SignatureSize), ed25519ProbeOptions)
	if e == nil {
		return ""
	}
	return e.Error()
})

// ed25519Usable reports whether an Ed25519 public key is one the verifier can
// work with. Unlike ed25519.Verify, which answers false for a bad key and a
// bad signature alike, VerifyWithOptions separates them: a key that is not a
// point on the curve — or is encoded above the field prime — is reported as a
// bad public key, while a usable key reports only that the signature is
// wrong. Accepting nothing but the latter makes this fail closed.
func ed25519Usable(publicKey string) error {
	raw, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return fmt.Errorf("not base64: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return fmt.Errorf("is %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}

	want := ed25519BadSignature()
	if want == "" {
		// Nothing to compare against; leave the judgement to the runtime
		// rather than invent a failure.
		return nil
	}
	e := ed25519.VerifyWithOptions(raw, ed25519ProbeMessage,
		make([]byte, ed25519.SignatureSize), ed25519ProbeOptions)
	if e != nil && e.Error() != want {
		return e
	}
	return nil
}

// ecdhCurve returns the curve behind a DNSSEC ECDSA algorithm, or nil for
// every other algorithm. crypto/ecdh is used only as a point checker here —
// it validates on-curve-ness on parse, which is the part the signature probe
// above cannot reach. Ed25519 and Ed448 have no equivalent parse-time test in
// the standard library, so a non-canonical point there is still only caught
// when a real signature is verified.
func ecdhCurve(alg uint8) ecdh.Curve {
	switch alg {
	case dns.ECDSAP256SHA256:
		return ecdh.P256()
	case dns.ECDSAP384SHA384:
		return ecdh.P384()
	}
	return nil
}

// usablePort resolves a port the way the net package does and returns the
// number it lands on. SplitHostPort only separates the halves — it never reads
// them — so ":65536" survives it and then fails at bind time, and an upstream
// with a port that big fails on every dial instead.
//
// LookupPort is the call the net package itself makes when it dials or
// listens, which is why it is used here rather than a numeric range check: it
// also accepts the service names ("domain", "https") that a plain number test
// would wrongly reject, and ":domain" does listen on 53. Both protocols are
// tried because sdns listens on each and the two tables can differ; accepting
// a name either one knows can only avoid refusing a config that works.
//
// The networks a caller passes are the ones the endpoint actually opens, so a
// service name is judged the way it will be looked up: bind serves UDP and TCP
// both, DoQ is UDP, and the TLS, DoH and API listeners are TCP.
//
// Callers that cannot use port 0 test the returned number rather than the
// string: "00" and "+0" both resolve to zero and would slip past a comparison
// against "0".
// lookupPort is net.LookupPort, as a variable so a test can record which
// networks each caller asks about. The service tables on a developer machine
// are not partitioned by protocol, so recording the question is the only way
// to pin that a DoT upstream is judged over TCP and a listener over what it
// actually opens.
var lookupPort = net.LookupPort

func usablePort(port string, networks ...string) (int, error) {
	resolved, first := 0, true
	for _, network := range networks {
		n, err := lookupPort(network, port)
		if err != nil {
			return 0, fmt.Errorf("port %q is not one this host can use for %s", port, network)
		}
		if first {
			resolved, first = n, false
			continue
		}
		if n != resolved {
			// A service name can sit at different numbers in the two
			// tables — "raid-am" is 2007 over UDP and 2013 over TCP on a
			// Mac. A setting that opens both would answer on one and wait
			// for the fallback on the other, which is the same split that
			// makes port 0 unusable there.
			return 0, fmt.Errorf("port %q resolves to %d for %s and %d for the other transport this setting opens; name a number",
				port, n, network, resolved)
		}
	}
	return resolved, nil
}

// validIPPort reports whether addr is an IP literal with a usable port.
// Authority and fallback servers are dialled directly, so a hostname there
// would need a resolver this one may not have yet.
func validIPPort(addr string, networks ...string) bool {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return false
	}
	if n, err := usablePort(port, networks...); err != nil || n == 0 {
		return false
	}
	return net.ParseIP(host) != nil
}

// validUpstream reports whether addr is one of the three forms a forwarder
// upstream may take. It mirrors what middleware/forwarder accepts, so a config
// that passes here is one the forwarder can actually use.
func validUpstream(addr string) error {
	switch {
	case strings.HasPrefix(addr, "https://"):
		// DoH may name a host: it is bootstrapped once at startup. What the
		// forwarder actually uses is Hostname(), not Host — "https://:443/x"
		// has a Host and no hostname, and is dropped during bootstrap.
		u, err := url.Parse(addr)
		if err != nil || u.Hostname() == "" {
			return fmt.Errorf("not a usable DoH URL")
		}
		if port := u.Port(); port != "" {
			n, err := usablePort(port, "tcp")
			if err != nil {
				return err
			}
			if n == 0 {
				return fmt.Errorf("port 0 has nothing to connect to")
			}
		}
		return nil
	case strings.HasPrefix(addr, "tls://"):
		if !validIPPort(strings.TrimPrefix(addr, "tls://"), "tcp") {
			return fmt.Errorf("DoT needs an IP address and port, e.g. tls://192.0.2.1:853")
		}
		return nil
	default:
		// Plain DNS asks over UDP and comes back over TCP when an answer
		// does not fit, so the port has to work for both.
		if !validIPPort(addr, "udp", "tcp") {
			return fmt.Errorf("must be an IP address and port, a tls:// address, or an https:// URL")
		}
		return nil
	}
}

// validateLoaded is Validate plus the requirements that only a configuration
// file has to meet. A Config built in code — a test, an embedder — supplies
// what it needs directly and legitimately leaves the rest empty, so these
// cannot live in Validate itself. They belong to the same report all the same:
// finding them one run later is exactly what the single gate exists to avoid.
func (c *Config) validateLoaded() error {
	var problems []string
	add := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	// Load creates this directory and then works inside it; empty reaches
	// os.Mkdir("") a few lines on and fails there, past the report.
	if strings.TrimSpace(c.Directory) == "" {
		add("directory: required, and this file leaves it empty")
	}

	// A root server is required of every file, forwarders included. The
	// resolver is constructed either way and its background goroutine primes
	// the root as soon as the middleware is ready — an empty list stops the
	// process there, before any query arrives. Forwarding only keeps the
	// resolver out of the query path, not out of the process.
	roots6 := len(c.Root6Servers)
	if !c.IPv6Access {
		// The resolver only takes the v6 list when v6 is in use, so a file
		// carrying nothing else has an empty root set at runtime.
		roots6 = 0
	}
	if len(c.RootServers) == 0 && roots6 == 0 {
		add("rootservers: none configured, and priming an empty root list stops the server at startup")
	}

	if err := c.Validate(); err != nil {
		if len(problems) == 0 {
			return err
		}
		// One list, in the shape Validate already reports.
		return fmt.Errorf("%w\n  - %s", err, strings.Join(problems, "\n  - "))
	}
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("invalid configuration:\n  - %s", strings.Join(problems, "\n  - "))
}

// validateRPZ judges the [rpz] block, only when the feature is on: a stale
// zone entry under a disabled section has no effect and must not refuse a
// config that has run for years. Zone files are parsed with the same
// loader the runtime uses, so `sdns -t` answers for the feed exactly as
// startup would read it.
func (c *Config) validateRPZ(add func(string, ...any)) {
	if !c.RPZ.Enabled {
		return
	}

	switch c.RPZ.Mode {
	case "shadow", "enforce":
	default:
		// Load fills an omitted mode with "shadow" before this runs, so
		// anything else here is a spelling that will stop startup.
		add("rpz.mode = %q: must be \"shadow\" or \"enforce\"", c.RPZ.Mode)
	}

	if len(c.RPZ.Zones) == 0 {
		add("rpz is enabled but lists no zones; either add a [[rpz.zone]] or disable it")
		return
	}
	// The bound the sidecar observation lists are sized by (design §5.6);
	// BIND's own response-policy limit is the same order.
	if len(c.RPZ.Zones) > 64 {
		add("rpz lists %d zones; at most 64 are supported", len(c.RPZ.Zones))
		return
	}

	seen := make(map[string]int, len(c.RPZ.Zones))
	for i, zc := range c.RPZ.Zones {
		where := fmt.Sprintf("rpz.zone[%d]", i)
		if zc.Name == "" {
			add("%s: name is required; it labels the zone in metrics and logs", where)
		} else if prev, dup := seen[zc.Name]; dup {
			add("%s: name %q is already used by rpz.zone[%d]", where, zc.Name, prev)
		} else {
			seen[zc.Name] = i
		}

		policy, ok := rpz.ParseOverride(zc.Policy)
		if !ok {
			add("%s: policy = %q: must be one of given, passthru, nxdomain, nodata, drop, tcp-only, cname, disabled",
				where, zc.Policy)
		}

		// The cname target is read exactly when the override is "cname":
		// required there, and a mistake anywhere else (the runtime would
		// silently ignore it, so the file says one thing and the server
		// does another).
		if policy == rpz.OverrideCNAME && ok {
			if zc.Cname == "" {
				add("%s: policy = \"cname\" needs a cname target", where)
			} else if _, valid := dns.IsDomainName(zc.Cname); !valid || !dns.IsFqdn(zc.Cname) {
				add("%s: cname = %q: must be a fully qualified domain name (with the trailing dot)", where, zc.Cname)
			}
		} else if zc.Cname != "" {
			add("%s: cname is set but policy is %q; the target is only read with policy = \"cname\"", where, zc.Policy)
		}

		if zc.File == "" {
			add("%s: file is required", where)
			continue
		}
		z, err := rpz.LoadZoneFile(zc.Name, zc.File, policy, dns.CanonicalName(zc.Cname))
		if err != nil {
			add("%s: %v", where, err)
			continue
		}
		if z.Rules == 0 {
			add("%s: %s loaded but compiled no rules (skipped: %v); the zone would filter nothing",
				where, zc.File, z.Skipped)
		}
	}
}
