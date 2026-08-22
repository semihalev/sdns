package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/authority"
	"github.com/semihalev/sdns/internal/cache"
	"github.com/semihalev/sdns/internal/contextutil"
	"github.com/semihalev/sdns/internal/dnsname"
	"github.com/semihalev/sdns/internal/dnsutil"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/resolver/dnssec"
	"github.com/semihalev/zlog/v2"
	"golang.org/x/sync/errgroup"
)

// Resolver type.
type Resolver struct {
	sync.RWMutex

	delegations *authority.Cache

	cfg *config.Config

	rootServers *authority.Servers

	outboundIPv4 []net.IP
	outboundIPv6 []net.IP

	// Pre-built *net.UDPAddr forms of the outbound IPs above, so the
	// UDP fast-path in exchange can skip the per-call allocation of
	// `&net.UDPAddr{IP: …}`. Indices align with outboundIPv4/IPv6.
	outboundUDPv4 []*net.UDPAddr
	outboundUDPv6 []*net.UDPAddr

	// resolveTarget, when set, remaps an upstream server address to a dial
	// target just before exchange dials it. Production leaves it nil (the
	// UDP fast path is untouched); hermetic tests Store a mapper to redirect
	// TEST-NET-1 (192.0.2.0/24) glue to loopback listeners so a real
	// root->parent->child->sub referral chain can be driven in-process. It
	// is atomic because the background priming goroutine dials concurrently
	// with a test setting the mapper — a plain field would race.
	resolveTarget atomic.Pointer[func(addr string) string]

	// glue addrs cache
	glueV4 *cache.Cache
	glueV6 *cache.Cache

	dnssec   bool
	rootKeys []dns.RR
	// configuredRootKeys is the immutable snapshot of cfg.RootKeys
	// parsed at startup. rootKeys above is the *current* trust set
	// and is rewritten by AutoTA on every refresh; the merge path in
	// AutoTA needs the original admin-configured anchors so that a
	// key which has aged out of the RFC 5011 lifecycle can't be
	// resurrected from the mutable copy on the next refresh.
	configuredRootKeys []dns.RR

	// qnameMinCount is RFC 9156's MAX_MINIMISE_COUNT and qnameMinOneLabel
	// its MINIMISE_ONE_LAB. Resolve them through
	// config.QnameMinimizeParams so a directly built Resolver cannot end up
	// grouping from the first query.
	qnameMinCount    int
	qnameMinOneLabel int
	netTimeout       time.Duration
	workPolicy       middleware.RecursionWorkPolicy

	sfGroup *SingleflightWrapper

	// TCP connection pool for persistent connections
	tcpPool *TCPConnPool

	// Circuit breaker and goroutine limiter
	circuitBreaker  *circuitBreaker
	maxConcurrent   chan struct{} // Semaphore for limiting concurrent queries
	v6LookupSlots   chan struct{} // Global cap on detached IPv6 NS enrichment jobs
	probeSlots      chan struct{} // Global cap on exploration probes outliving their lookup
	resolutionSlots chan struct{} // Hard ceiling on in-flight zone lookups; full → fail fast
	zoneInflight    *zoneInflightLimiter
	cryptoLimiter   *dnssec.CryptoLimiter

	// store is the cache facade used by subQuery for resolver-private
	// DNSSEC record lookups (DS, DNSKEY). Auto-wired during
	// middleware.Setup via StoreSetter; nil-safe for tests that
	// construct a Resolver directly.
	//
	// atomic.Pointer because r.run() starts a background goroutine
	// from NewResolver that issues priming sub-queries the instant
	// middleware.Ready() returns true — and the auto-wire write
	// happens after NewResolver returns. Production sequences the
	// autoWire() call before globalPipeline.Store, but tests
	// construct fresh Resolvers outside that flow and need the
	// atomic barrier for correctness under -race.
	store atomic.Pointer[middleware.Store]

	// queryer drives policy-aware internal lookups (NS A/AAAA, DNAME
	// target) through the sub-pipeline so operator overrides
	// (hostsfile, blocklist, kubernetes, as112) and failover still
	// apply. Auto-wired via QueryerSetter. Same atomic.Pointer
	// reasoning as store.
	queryer atomic.Pointer[middleware.Queryer]
}

// resolveState holds the state for a DNS resolution operation.
//
// requestID is the outer client request's dns.Msg.Id, used by newDialer to
// pick a stable outbound IP per query. It is sourced from
// contextKeyRequestID when present (so Queryer-dispatched sub-queries
// inherit the outer client's spread through the shared ctx), with req.Id
// as a fallback for direct callers.
type resolveState struct {
	req     *dns.Msg
	servers *authority.Servers
	depth   int
	level   int
	// minSteps counts the minimized queries already sent for this request.
	// RFC 9156 section 2.3 bounds outgoing queries per user request, so the
	// budget is spent by probes actually sent — not by how deep the closest
	// cached delegation happens to sit. Capping on level instead would hand
	// a warm resolver a budget already consumed by labels it never had to
	// expose, and stop minimizing exactly where the remaining labels are the
	// private ones.
	minSteps int
	// minExposed is how many labels the last minimized query carried. A
	// grouped query exposes more than one label at a time, so advancing by
	// one would re-send a name shorter than the one already on the wire.
	minExposed int
	nomin      bool
	parentDS   []dns.RR
	isRoot     bool
	extra      []bool
	requestID  uint16
	work       *middleware.RecursionWorkLedger

	// cutDeadline is the absolute expiry of the shallowest delegation on
	// the path descended so far (zero = unbounded, at/above root). A newly
	// established delegation inherits it via min, so a deep sub-delegation
	// can never outlive an ancestor cut — the Phoenix downward-delegation
	// (T2) protection (GHSA-mqfw-f48p-2vc8).
	cutDeadline time.Time
	cutKey      uint64
}

// advance moves past what the query just answered exposed: the labels the
// minimized query actually carried, or one more label when the full name went
// out. The two agree whenever minimization added a single label, which is
// every name shallower than the grouping threshold.
func (rs *resolveState) advance(minimized bool) {
	if minimized {
		rs.level = rs.minExposed
		return
	}

	rs.level++
}

// minNonZero returns the earlier of two deadlines, treating a zero time as
// "unbounded" (so it never wins). Zero for both returns zero.
func minNonZero(a, b time.Time) time.Time {
	switch {
	case a.IsZero():
		return b
	case b.IsZero():
		return a
	case a.Before(b):
		return a
	default:
		return b
	}
}

// minCut returns the earliest bounded cut together with the identity that
// supplied it. Zero deadlines are unbounded. On equal deadlines the first
// cut wins, preserving the ancestor identity when a descendant inherits the
// exact same absolute expiry.
func minCut(a time.Time, aKey uint64, b time.Time, bKey uint64) (time.Time, uint64) {
	switch {
	case a.IsZero():
		return b, bKey
	case b.IsZero():
		return a, aKey
	case b.Before(a):
		return b, bKey
	default:
		return a, aKey
	}
}

// noteCut folds a delegation-cut deadline into the request tree's
// ResponseMeta sink (established by the cache middleware or
// DNSHandler.ServeDNS). The cache layer reads the accumulated minimum
// back when storing the answer, so a cached answer can never outlive
// the delegation cut that produced it (GHSA-mqfw-f48p-2vc8,
// answer-cache ghost). No-op when ctx carries no sink (priming,
// background work) or the deadline is zero.
func noteCut(ctx context.Context, deadline time.Time, key uint64) {
	middleware.ResponseMetaFrom(ctx).BoundCutFor(deadline, key)
}

type hostSet map[string]struct{}

// fatalResolverError marks an error that represents terminal failure of every
// authority server considered by a lookup. It must be a concrete wrapper:
// defining the marker as `type fatalError error` makes every non-nil error
// satisfy the interface assertion and incorrectly attributes local failures
// to the authority zone.
type fatalResolverError struct {
	cause error
}

func (e *fatalResolverError) Error() string { return e.cause.Error() }
func (e *fatalResolverError) Unwrap() error { return e.cause }

func fatalError(cause error) error {
	if cause == nil {
		return nil
	}
	return &fatalResolverError{cause: cause}
}

func isFatalError(err error) bool {
	var target *fatalResolverError
	return errors.As(err, &target)
}

// Error variables are defined in errors.go

const (
	rootzone         = "."
	maxUint16        = 1 << 16
	defaultCacheSize = 1024 * 256
	defaultTimeout   = 2 * time.Second

	// maxInflightProbes caps the exploration probes allowed to outlive the
	// lookup that started them.
	//
	// Sixteen is chosen from what the slots turn over rather than from what
	// a machine could carry: a probe to a server that answers is done in
	// the time that server takes, so these sustain a hundred-odd
	// measurements a second against a delegation that needs a few dozen in
	// its lifetime. Only a probe to something silent holds a slot for a
	// whole timeout, and sixteen of those is a number nobody has to think
	// about. What it must not do is grow with arrival rate, which is how a
	// detached pool in this file once reached 1.4M goroutines.
	maxInflightProbes = 16

	// probeGrace is how much longer than one upstream timeout a probe's
	// context lives, so a silent server is ended by the socket deadline —
	// which records a failure — rather than by the context, which would
	// only record a cancellation.
	probeGrace = 250 * time.Millisecond
)

// NewResolver return a resolver.
func NewResolver(cfg *config.Config) *Resolver {
	workPolicy := middleware.MustRecursionWorkPolicyFromConfig(cfg.RecursionFirewall)

	r := &Resolver{
		cfg: cfg,

		delegations: authority.NewCache(),

		rootServers: new(authority.Servers),

		glueV4: cache.New(defaultCacheSize),

		dnssec: cfg.DNSSEC == "on",

		netTimeout:     defaultTimeout,
		workPolicy:     workPolicy,
		sfGroup:        NewSingleflightWrapper(),
		circuitBreaker: newCircuitBreaker(),
		cryptoLimiter:  dnssec.NewCryptoLimiter(workPolicy.MaxConcurrentCrypto),
	}

	r.qnameMinCount, r.qnameMinOneLabel = cfg.QnameMinimizeParams()

	// Set default for MaxConcurrentQueries if not configured
	maxConcurrent := cfg.MaxConcurrentQueries
	if maxConcurrent == 0 {
		maxConcurrent = 1000 // Default to 1000 concurrent queries
	}
	r.maxConcurrent = make(chan struct{}, maxConcurrent)
	r.resolutionSlots = make(chan struct{}, maxConcurrent)
	// Destination fairness: one hanging zone may pin at most a small slice
	// of the in-flight budget, so a partial outage of a popular authority
	// set (one provider's network) can never starve resolution for the
	// healthy rest of the namespace.
	r.zoneInflight = newZoneInflightLimiter(max(maxConcurrent/16, 16))

	if r.cfg.IPv6Access {
		r.glueV6 = cache.New(defaultCacheSize)
		// Detached V6 enrichment shares the query budget's scale: during a
		// network incident every referral wants one of these jobs, and an
		// uncapped pool grows at arrival-rate × timeout (2026-07-28: 1.4M
		// goroutines). Full slots shed the job instead of queueing it.
		r.v6LookupSlots = make(chan struct{}, maxConcurrent)
	}

	r.probeSlots = make(chan struct{}, maxInflightProbes)

	if r.cfg.Timeout.Duration > 0 {
		r.netTimeout = r.cfg.Timeout.Duration
	}

	r.parseRootServers(cfg)
	r.parseOutBoundAddrs(cfg)

	r.rootKeys = []dns.RR{}
	for _, k := range cfg.RootKeys {
		rr, err := dns.NewRR(k)
		if err != nil {
			zlog.Fatal("Root keys invalid", zlog.String("error", err.Error()))
		}
		r.rootKeys = append(r.rootKeys, rr)
	}
	r.configuredRootKeys = slices.Clone(r.rootKeys)

	// Initialize TCP connection pool if enabled
	if cfg.TCPKeepalive {
		r.tcpPool = NewTCPConnPool(
			cfg.RootTCPTimeout.Duration,
			cfg.TLDTCPTimeout.Duration,
			cfg.TCPMaxConnections,
		)
	}

	go r.run()

	return r
}

func (r *Resolver) parseRootServers(cfg *config.Config) {
	r.rootServers = &authority.Servers{}
	r.rootServers.Zone = rootzone
	seen := make(map[string]struct{})

	for _, s := range cfg.RootServers {
		host, _, _ := net.SplitHostPort(s)

		if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
			key := middleware.CanonicalResolutionEndpoint(s)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			r.rootServers.List = append(r.rootServers.List, authority.NewServer(s, authority.IPv4))
		}
	}

	if cfg.IPv6Access {
		for _, s := range cfg.Root6Servers {
			host, _, _ := net.SplitHostPort(s)

			if ip := net.ParseIP(host); ip != nil && ip.To16() != nil {
				key := middleware.CanonicalResolutionEndpoint(s)
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				r.rootServers.List = append(r.rootServers.List, authority.NewServer(s, authority.IPv6))
			}
		}
	}
}

func (r *Resolver) parseOutBoundAddrs(cfg *config.Config) {
	for _, s := range cfg.OutboundIPs {
		if ip := net.ParseIP(s); ip != nil && ip.To4() != nil {
			if isLocalIP(ip) {
				r.outboundIPv4 = append(r.outboundIPv4, ip)
			} else {
				zlog.Fatal("Invalid local IPv4 address in config", zlog.String("ip", ip.String()))
			}
		}
	}

	if cfg.IPv6Access {
		for _, s := range cfg.OutboundIP6s {
			if ip := net.ParseIP(s); ip != nil && ip.To16() != nil {
				if isLocalIP(ip) {
					r.outboundIPv6 = append(r.outboundIPv6, ip)
				} else {
					zlog.Fatal("Invalid local IPv6 address in config", zlog.String("ip", ip.String()))
				}
			}
		}
	}

	// Pre-build UDPAddr forms so the UDP hot path doesn't allocate
	// one per exchange. Port=0 means "kernel picks" — the ephemeral
	// port is bound at socket creation, just like the Dialer path.
	r.outboundUDPv4 = make([]*net.UDPAddr, len(r.outboundIPv4))
	for i, ip := range r.outboundIPv4 {
		r.outboundUDPv4[i] = &net.UDPAddr{IP: ip}
	}
	r.outboundUDPv6 = make([]*net.UDPAddr, len(r.outboundIPv6))
	for i, ip := range r.outboundIPv6 {
		r.outboundUDPv6[i] = &net.UDPAddr{IP: ip}
	}
}

// (*Resolver).Resolve resolve starts a DNS resolution - public interface with old signature for compatibility.
func (r *Resolver) Resolve(ctx context.Context, req *dns.Msg, servers *authority.Servers, root bool, depth int, level int, nomin bool, parentDS []dns.RR, extra ...bool) (*dns.Msg, error) {
	ctx = dnssec.EnsureNSEC3HashMemo(ctx)
	ctx, _ = middleware.EnsureResolutionAttemptGuard(ctx)
	hadWork := middleware.RecursionWorkFrom(ctx) != nil
	ctx, work := middleware.EnsureRecursionWork(ctx, r.workPolicy)
	// Test ownership after Ensure. A LazyDeadline pin remains root-owned across
	// its pending -> active transition, while a direct Resolver caller owns and
	// must finish the standalone ledger Ensure just created. Keeping ownership
	// encoded in the pin avoids a call-order-dependent double finish.
	rootOwnsWork := middleware.RecursionWorkRootOwned(ctx)
	if !rootOwnsWork && !hadWork && work != nil {
		defer middleware.FinishRecursionWork(ctx)
	}
	if work != nil {
		if err := work.EnforcementError(); err != nil {
			return nil, err
		}
	}

	reqid := req.Id
	if v := requestIDFromContext(ctx); v != nil {
		if id, ok := v.(uint16); ok {
			reqid = id
		}
	}
	rs := &resolveState{
		req:       req,
		servers:   servers,
		depth:     depth,
		level:     level,
		nomin:     nomin,
		parentDS:  parentDS,
		isRoot:    root,
		extra:     extra,
		requestID: reqid,
		work:      work,
	}
	resp, err := r.resolve(ctx, rs)
	if work != nil {
		if workErr := work.EnforcementError(); workErr != nil {
			return nil, workErr
		}
	}
	return resp, err
}

// resolve performs the actual DNS resolution with cleaner parameters.
func (r *Resolver) resolve(ctx context.Context, rs *resolveState) (*dns.Msg, error) {
	q := rs.req.Question[0]

	if rs.isRoot {
		m := r.searchCache(q, rs.req.CheckingDisabled, q.Name)
		rs.servers, rs.parentDS, rs.level = m.servers, m.parentDS, m.level
		// Seed the cut deadline from the deepest cached delegation so any
		// delegation established below it inherits this bound.
		rs.cutDeadline, rs.cutKey = minCut(rs.cutDeadline, rs.cutKey, m.deadline, m.key)
		noteCut(ctx, rs.cutDeadline, rs.cutKey)
	}

	// RFC 9156 query minimization, bounded by qnameMinCount probes per
	// request. Lowering that bound is a privacy/latency trade: past it the
	// full name goes out, so every remaining delegation sees all of it.
	minReq, minExposed, minimized := r.minimize(rs.req, rs.level, rs.minSteps, rs.nomin)
	if minimized {
		rs.minSteps++
		rs.minExposed = minExposed
	}

	if debugLogEnabled() {
		zlog.Debug("Query inserted", "reqid", minReq.Id, "zone", rs.servers.Zone, "query", dnsutil.FormatQuestion(minReq.Question[0]), "cd", rs.req.CheckingDisabled, "qname-minimize", minimized)
	}

	resp, err := r.groupLookup(ctx, rs, minReq, rs.servers, minimized)
	if err != nil {
		return r.handleLookupError(ctx, err, rs, minReq, minimized)
	}

	resp = r.setTags(rs.req, resp)
	serverFailureResponse := false
	if resp.Rcode != dns.RcodeSuccess {
		responseType, _ := dnsutil.ClassifyResponse(resp, time.Now())
		serverFailureResponse = responseType == dnsutil.TypeServerFailure
	}

	if resp.Rcode != dns.RcodeSuccess && len(resp.Answer) == 0 && len(resp.Ns) == 0 {
		if minimized {
			rs.advance(minimized)
			rs.isRoot = false
			return r.resolve(ctx, rs)
		}
		if serverFailureResponse {
			r.recordResolutionZoneFailure(ctx, rs.req.Question[0], rs.servers.Zone, nil)
		} else {
			r.clearResolutionZoneFailure(rs.req.Question[0], rs.servers.Zone)
		}
		return resp, nil
	}

	if !minimized && len(resp.Answer) > 0 {
		// this is like auth server external cname error but this can be recover.
		if len(resp.Answer) > 0 && (resp.Rcode == dns.RcodeServerFailure || resp.Rcode == dns.RcodeNameError) {
			resp.Rcode = dns.RcodeSuccess
		}

		if resp.Rcode == dns.RcodeNameError {
			result, resultErr := r.authority(ctx, rs.req, resp, rs.parentDS, rs.servers.Zone)
			if resultErr == nil {
				r.clearResolutionZoneFailure(rs.req.Question[0], rs.servers.Zone)
			}
			return result, resultErr // handle NXDOMAIN with DNSSEC proof
		}

		result, resultErr := r.answer(ctx, rs.req, resp, rs.parentDS, rs.servers.Zone, rs.extra...)
		if resultErr == nil {
			r.clearResolutionZoneFailure(rs.req.Question[0], rs.servers.Zone)
		}
		return result, resultErr
	}

	if minimized && (len(resp.Answer) == 0 && len(resp.Ns) == 0) || len(resp.Answer) > 0 {
		rs.advance(minimized)
		rs.isRoot = false
		return r.resolve(ctx, rs)
	}

	if len(resp.Ns) > 0 {
		return r.processAuthoritySection(ctx, rs, minReq, resp, minimized) // handle delegation or authority data
	}

	// no answer, no authority. create new msg safer, sometimes received weird responses
	m := new(dns.Msg) // return clean empty response instead of malformed data

	m.Question = rs.req.Question
	m.SetRcode(rs.req, dns.RcodeSuccess)
	m.RecursionAvailable = true
	m.Extra = rs.req.Extra

	return m, nil
}

// groupLookup collapses concurrent identical lookups onto one leader
// through singleflight. owned declares the request handed over: the leader
// closure may retain and read it past this call's return, so owned=true is
// only correct when nothing upstack mutates req afterward — today that is
// exactly minimize's private copy, which handleLookupError at most reads.
// A shared request (rs.req) must pass owned=false so the leader gets its
// own copy, made while the caller still exclusively owns the memory.
func (r *Resolver) groupLookup(ctx context.Context, rs *resolveState, req *dns.Msg, servers *authority.Servers, owned bool) (resp *dns.Msg, err error) {
	q := req.Question[0]

	// Key by question, CD flag, AND a fingerprint of the
	// authority set. Two lookups for the same qname/qtype at
	// different recursion stages (e.g. unminimised root-side
	// retry vs. warm child-zone lookup) target different
	// delegations, and the same zone name can be backed by a
	// different set of servers after an IPv6-NS discovery
	// append or a re-delegation. Collapsing those into one
	// singleflight call would return a response produced
	// against an unrelated delegation path. CD also has to
	// participate because the validator result differs.
	//
	// The parent-DS chain is deliberately *not* in the key: the
	// singleflight leader only does the upstream wire lookup
	// (r.lookup), which doesn't consume parentDS. DNSSEC
	// validation runs per-caller on the copied response with each
	// caller's own DS chain, so mixing parentDS into the key
	// would fragment dedup without affecting correctness.
	cd := byte('0')
	if req.CheckingDisabled {
		cd = '1'
	}
	key := strconv.FormatUint(cache.Key(q), 10) + "|" + servers.Zone +
		"|" + string(cd) + "|" + strconv.FormatUint(servers.Fingerprint(), 10)

	// The leader closure can outlive this caller: TimedDoChan returns on this
	// caller's timeout/cancel while the shared generation remains registered
	// until its closure finishes (or bounded stuck cleanup retires it). After
	// we return, a shared req resumes its lifecycle upstack — the response
	// re-attaches the request OPT and the edns writer mutates it in place —
	// so an abandoned leader copying req (lookup's per-server CopyTo) would
	// race on caller-owned memory. Hand the closure its own private copy,
	// made here while we still exclusively own req.
	//
	// An owned req (a minimized copy) needs no second copy: the leader only
	// reads it — per-server CopyTo sources from it, queryServer mutates the
	// copies — and after we return its only touch upstack is a read in
	// handleLookupError's debug log before it is dropped.
	leaderReq := req
	if !owned {
		leaderReq = req.Copy()
	}

	for {
		// Use TimedDoChan for automatic timeout handling. When a follower
		// receives the leader's request-local policy or lifecycle error, it
		// re-enters the same key under its own still-live context. The
		// completed call has already been removed by singleflight, so
		// concurrent followers collapse onto one new leader without a racy
		// Forget or N parallel lookups. If that leader also fails locally, it
		// returns its own error while the remaining healthy followers regroup
		// again; each caller's context bounds the sequence.
		result, shared, leader, lookupErr := r.sfGroup.TimedDoChanWithRole(ctx, key, func() (any, error) {
			// Hard ceiling on in-flight zone lookups, held only for this
			// wire-level lookup — never across recursion levels, so a
			// nested sub-lookup can't deadlock on its parent's slot. When
			// every slot is pinned by lookups waiting out dead upstreams,
			// new work is shed immediately instead of joining the queue:
			// during a partial outage the queue's growth rate is
			// arrival-rate × timeout and it never drains (2026-07-28).
			// A nil pool (bare test resolvers) disables the ceiling.
			if r.resolutionSlots != nil {
				select {
				case r.resolutionSlots <- struct{}{}:
				default:
					shedGlobalCapacity.Inc()
					return nil, errResolutionCapacity
				}
				defer func() { <-r.resolutionSlots }()
			}
			// Per-zone quota (BIND fetches-per-zone analog): the global
			// pool is blind to WHO holds its slots, so without this a
			// single popular destination going dark would pin slots at
			// arrival-rate × timeout and shed healthy zones along with
			// the dead one. A zone at its quota is shed by itself;
			// everyone else keeps resolving at full speed.
			if r.zoneInflight != nil {
				release, ok := r.zoneInflight.acquire(servers.Zone)
				if !ok {
					shedZoneCapacity.Inc()
					return nil, errZoneCapacity
				}
				defer release()
			}
			return r.lookup(ctx, rs, leaderReq, servers)
		})

		if lookupErr != nil {
			if shared && !leader && middleware.IsRequestLocalResolutionError(lookupErr) {
				if ctxErr := contextutil.EffectiveError(ctx); ctxErr != nil {
					return nil, ctxErr
				}
				continue
			}
			return nil, lookupErr
		}

		resp = result.(*dns.Msg)
		if resp != nil {
			// Only copy when the response is actually shared with another
			// goroutine. In the uncontended hot path we own the only
			// reference and can mutate the ID in place.
			if shared {
				resp = resp.Copy()
			}
			resp.Id = req.Id
		}
		return resp, nil
	}
}

func (r *Resolver) checkLoop(ctx context.Context, qname string, qtype uint16) (context.Context, bool) {
	key := contextKeyNSList + contextKey(qtype)

	if v := ctx.Value(key); v != nil {
		list := v.([]string)

		loopCount := 0
		for _, n := range list {
			if n == qname {
				loopCount++
				if loopCount > 1 {
					return ctx, true // detected NS lookup loop, prevent infinite recursion
				}
			}
		}

		list = append(list, qname)
		ctx = context.WithValue(ctx, key, list)
	} else {
		ctx = context.WithValue(ctx, key, []string{qname})
	}

	return ctx, false
}

func (r *Resolver) checkHosts(ctx context.Context, servers *authority.Servers) (ok bool) {
	// Quick check under read lock
	servers.RLock()
	oldsize := len(servers.List)
	if servers.Checked || dns.CountLabel(servers.Zone) < 2 {
		servers.RUnlock()
		return false
	}
	hostsToCheck := make([]string, len(servers.Hosts))
	copy(hostsToCheck, servers.Hosts)
	cd := servers.CheckingDisable
	servers.RUnlock()

	// Use errgroup for concurrent lookups
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(10) // Maximum 10 concurrent lookups

	type lookupResult struct {
		name   string
		addrs  []netip.Addr
		isIPv6 bool
	}
	results := make(chan lookupResult, len(hostsToCheck)*2)

	// Clear caches and start IPv4 lookups
	for _, name := range hostsToCheck {
		name := name // Capture loop variable
		r.removeIPv4Cache(name)

		g.Go(func() error {
			addrs, err := r.lookupNSAddrV4(ctx, name, cd)
			if err == nil && len(addrs) > 0 {
				select {
				case results <- lookupResult{name: name, addrs: addrs, isIPv6: false}:
				case <-ctx.Done():
				}
			}
			return nil // Don't fail the group
		})
	}

	// Start IPv6 lookups if enabled
	if r.cfg.IPv6Access {
		for _, name := range hostsToCheck {
			name := name // Capture loop variable
			r.removeIPv6Cache(name)

			g.Go(func() error {
				addrs, err := r.lookupNSAddrV6(ctx, name, cd)
				if err == nil && len(addrs) > 0 {
					select {
					case results <- lookupResult{name: name, addrs: addrs, isIPv6: true}:
					case <-ctx.Done():
					}
				}
				return nil // Don't fail the group
			})
		}
	}

	// Close results channel when all lookups complete
	go func() {
		_ = g.Wait()
		close(results)
	}()

	// Collect results
	nsipv4 := make(map[string][]netip.Addr)
	nsipv6 := make(map[string][]netip.Addr)
	var newServers []*authority.Server

	for result := range results {
		if result.isIPv6 {
			nsipv6[result.name] = result.addrs
			for _, addr := range result.addrs {
				newServers = append(newServers, authority.NewServerFromAddrPort(netip.AddrPortFrom(addr, 53)))
			}
		} else {
			nsipv4[result.name] = result.addrs
			for _, addr := range result.addrs {
				newServers = append(newServers, authority.NewServerFromAddrPort(netip.AddrPortFrom(addr, 53)))
			}
		}
	}

	// Update caches
	if len(nsipv4) > 0 {
		r.addIPv4Cache(nsipv4)
	}
	if len(nsipv6) > 0 {
		r.addIPv6Cache(nsipv6)
	}

	// Update server list
	servers.Lock()
	defer servers.Unlock()

	// Deduplicate and add new servers
	existing := make(map[string]bool)
	for _, s := range servers.List {
		existing[middleware.CanonicalResolutionEndpoint(s.Addr)] = true
	}

	for _, newServer := range newServers {
		key := middleware.CanonicalResolutionEndpoint(newServer.Addr)
		if !existing[key] {
			servers.List = append(servers.List, newServer)
			existing[key] = true
		}
	}

	servers.Checked = true
	if oldsize != len(servers.List) {
		servers.InvalidateFingerprint()
		return true
	}
	return false
}

func (r *Resolver) checkGlueRR(resp *dns.Msg, hosts hostSet, level int) (*authority.Servers, hostSet, hostSet) {
	authservers := &authority.Servers{}
	seenServers := make(map[netip.AddrPort]struct{})

	foundv4 := make(hostSet)
	foundv6 := make(hostSet)

	if r.cfg.IPv6Access {
		nsipv6 := make(map[string][]netip.Addr)
		for _, a := range resp.Extra {
			if extra, ok := a.(*dns.AAAA); ok {
				name := strings.ToLower(extra.Header().Name)
				qname := resp.Question[0].Name

				i, _ := dns.PrevLabel(qname, level)

				if dnsname.CompareSuffix(name, qname[i:]) < level {
					// we cannot trust that glue, out of bailiwick.
					continue
				}

				if _, ok := hosts[name]; ok {
					addr, valid := usableAddr(extra.AAAA)
					if !valid {
						continue
					}

					foundv6[name] = struct{}{}

					nsipv6[name] = appendUniqueAddr(nsipv6[name], addr)
					endpoint := netip.AddrPortFrom(addr, 53)
					if _, ok := seenServers[endpoint]; !ok {
						seenServers[endpoint] = struct{}{}
						authservers.List = append(authservers.List, authority.NewServerFromAddrPort(endpoint))
					}
				}
			}
		}
		r.addIPv6Cache(nsipv6)
	}

	nsipv4 := make(map[string][]netip.Addr)
	for _, a := range resp.Extra {
		if extra, ok := a.(*dns.A); ok {
			name := strings.ToLower(extra.Header().Name)
			qname := resp.Question[0].Name

			i, _ := dns.PrevLabel(qname, level)

			if dnsname.CompareSuffix(name, qname[i:]) < level {
				// we cannot trust that glue, it doesn't cover in the origin name.
				continue
			}

			if _, ok := hosts[name]; ok {
				addr, valid := usableAddr(extra.A)
				if !valid {
					continue
				}

				foundv4[name] = struct{}{}

				nsipv4[name] = appendUniqueAddr(nsipv4[name], addr)
				endpoint := netip.AddrPortFrom(addr, 53)
				if _, ok := seenServers[endpoint]; !ok {
					seenServers[endpoint] = struct{}{}
					authservers.List = append(authservers.List, authority.NewServerFromAddrPort(endpoint))
				}
			}
		}
	}
	r.addIPv4Cache(nsipv4)

	return authservers, foundv4, foundv6
}

func (r *Resolver) addIPv4Cache(nsipv4 map[string][]netip.Addr) {
	for name, addrs := range nsipv4 {
		key := cache.Key(dns.Question{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET})
		r.glueV4.Add(key, addrs)
	}
}

func (r *Resolver) getIPv4Cache(name string) ([]netip.Addr, bool) {
	key := cache.Key(dns.Question{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET})
	if v, ok := r.glueV4.Get(key); ok {
		return v.([]netip.Addr), ok
	}

	return nil, false
}

func (r *Resolver) removeIPv4Cache(name string) {
	r.glueV4.Remove(cache.Key(dns.Question{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET}))
}

func (r *Resolver) addIPv6Cache(nsipv6 map[string][]netip.Addr) {
	for name, addrs := range nsipv6 {
		key := cache.Key(dns.Question{Name: name, Qtype: dns.TypeAAAA, Qclass: dns.ClassINET})
		r.glueV6.Add(key, addrs)
	}
}

func (r *Resolver) getIPv6Cache(name string) ([]netip.Addr, bool) {
	key := cache.Key(dns.Question{Name: name, Qtype: dns.TypeAAAA, Qclass: dns.ClassINET})
	if v, ok := r.glueV6.Get(key); ok {
		return v.([]netip.Addr), ok
	}

	return nil, false
}

func (r *Resolver) removeIPv6Cache(name string) {
	r.glueV6.Remove(cache.Key(dns.Question{Name: name, Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}))
}

// minimize shortens req to the labels the resolution has reached so far.
// level is how many labels are already exposed, steps how many minimized
// queries this request has spent — the budget RFC 9156 section 2.3 bounds. The
// returned count is the labels this query exposes, which the caller carries
// forward as the next level.
func (r *Resolver) minimize(req *dns.Msg, level, steps int, nomin bool) (*dns.Msg, int, bool) {
	if r.qnameMinCount == 0 || nomin {
		return req, level, false
	}

	q := req.Question[0]

	if steps >= r.qnameMinCount || q.Name == rootzone {
		return req, level, false
	}

	// RFC 9156 section 2.3: the first qnameMinOneLabel queries add a single
	// label, then whatever is still hidden is divided over the queries left,
	// the remainder falling to the last of them. Recomputing the quotient per
	// query reproduces that distribution — 18 labels under 10/4 gives
	// 1,1,1,1,2,2,2,2,3,3 — without carrying a schedule between calls.
	add := 1
	if steps >= r.qnameMinOneLabel {
		if left := r.qnameMinCount - steps; left > 0 {
			if grouped := (dns.CountLabel(q.Name) - level) / left; grouped > add {
				add = grouped
			}
		}
	}

	// RFC 9156 section 2.3: a label starting with an underscore is a service
	// tag — _tcp, _dmarc, a DKIM selector — not an administrative boundary, so
	// no zone cut hides behind it and asking about it separately buys nothing.
	// Take the whole run of them in this step. PrevLabel's end flag bounds the
	// loop, so the name is never counted.
	for {
		next, end := dns.PrevLabel(q.Name, level+add+1)
		if end || q.Name[next] != '_' {
			break
		}
		add++
	}

	prev, end := dns.PrevLabel(q.Name, level+add)
	if end {
		return req, level, false
	}
	minName := q.Name[prev:]
	if minName == q.Name {
		return req, level, false
	}

	// Only the outcome that queries a different name pays for a private
	// copy; every other path hands the caller's request back untouched,
	// exactly as the nomin/disabled entries above already do. The copy is
	// what makes the returned request lookup-owned — see groupLookup.
	minReq := req.Copy()
	minReq.Question[0].Name = minName
	return minReq, level + add, true
}

func (r *Resolver) setTags(req, resp *dns.Msg) *dns.Msg {
	resp.RecursionAvailable = true
	resp.RecursionDesired = true
	resp.Authoritative = false
	resp.CheckingDisabled = req.CheckingDisabled
	resp.AuthenticatedData = false

	return resp
}

// checkDname returns the target-side response for a DNAME redirect, or
// (nil, nil) when no DNAME applies. An error is returned when a DNAME
// *does* apply but the follow-up cannot be completed — in particular
// when the alias-chain depth cap is reached, since silently dropping
// the redirect would let an overlong or cyclic chain degrade into a
// NOERROR response containing only the outer DNAME and leave the
// client with an unresolved reference.
func (r *Resolver) checkDname(
	ctx context.Context,
	resp *dns.Msg,
) (*dns.Msg, *middleware.ResponseMeta, error) {
	if len(resp.Question) == 0 {
		return nil, nil, nil
	}

	q := resp.Question[0]

	if q.Qtype == dns.TypeCNAME {
		return nil, nil, nil
	}

	target := dnsutil.DnameTarget(resp)
	if target == "" {
		return nil, nil, nil
	}

	// Cap the DNAME alias chain. Each follow-up goes through
	// Queryer.Query which spawns a fresh resolveState and
	// resets the per-resolve depth counter, so without a
	// ctx-carried counter two zones that cross-DNAME each other
	// loop until the request deadline fires.
	depth, _ := ctx.Value(contextKeyDnameDepth).(int)
	if depth >= maxDnameDepth {
		zlog.Warn("DNAME alias chain too long", "qname", q.Name, "target", target, "depth", depth)
		return nil, nil, errMaxDepth
	}
	ctx = context.WithValue(ctx, contextKeyDnameDepth, depth+1)

	req := new(dns.Msg)
	req.SetQuestion(target, q.Qtype)
	req.SetEdns0(dnsutil.DefaultMsgSize, true)
	// Mirror the outer request's CD bit onto the follow-up. Without
	// this, a CD=1 client query can still have the DNAME target
	// leg re-validated and turned into SERVFAIL on bogus target
	// data — the opposite of what the client asked for. resp.
	// CheckingDisabled is set from req.CheckingDisabled in
	// setTags() so it's the authoritative source here.
	req.CheckingDisabled = resp.CheckingDisabled

	// The DNAME target is resolved and cached under its own name, so it
	// carries its own lineage rather than the outer DNAME's. The outer
	// answer inherits it only where the target is spliced in, which is
	// after validation and is the only place the target's records become
	// part of what the client is served.
	ctx, targetCut := middleware.WithForkedCut(ctx)

	msg, err := r.internalExchange(ctx, req)
	if err != nil {
		return nil, nil, err
	}
	return msg, targetCut, nil
}

func (r *Resolver) answer(ctx context.Context, req, resp *dns.Msg, parentDS []dns.RR, zone string, extra ...bool) (*dns.Msg, error) {
	// The internal recursion's target response is held back until
	// after the outer DNSSEC check. Merging target records into resp
	// before dnssec.VerifyRRSIG() would force the validator to tolerate
	// arbitrary out-of-zone names, which an attacker could abuse by
	// piggybacking unsigned foreign RRsets onto a signed DNAME
	// answer. By validating the outer response alone and merging the
	// target data afterward, dnssec.VerifyRRSIG sees only the signer zone's
	// records and the combined AD still reflects both sides.
	targetMsg, targetCut, err := r.checkDname(ctx, resp)
	if err != nil {
		// Depth cap or internal-exchange failure on the DNAME leg.
		// Surfacing the error prevents a cyclic/overlong DNAME chain
		// from being silently reported back as a NOERROR answer that
		// contains only the outer DNAME — the client would follow
		// that partial chain forever, so fail loud instead.
		return nil, err
	}

	if !req.CheckingDisabled {
		// Fail closed when trust anchors are unavailable. AutoTA
		// clears r.rootKeys on unrecoverable errors (e.g. corrupt
		// tombstone store); without a starting anchor no chain can
		// be validated, and letting the query proceed would silently
		// fall into the "unsigned delegation" path and accept
		// unauthenticated data.
		if r.dnssec && !r.hasTrustAnchors() {
			return nil, dnssec.ErrTrustAnchorsUnavailable
		}
		q := req.Question[0]

		signers := r.findRRSIGSigners(resp, q.Name, true)
		if len(signers) == 0 {
			// No RRSIGs in the response. Determine whether missing
			// signatures are acceptable (insecure delegation) or a
			// real DNSSEC failure (signed zone).
			if r.isZoneSecure(ctx, q.Name, parentDS, zone) {
				// The zone we queried is signed, but qname may live in an
				// unsigned child delegated below it that this same server
				// answered authoritatively (no referral crossed). Accept
				// the unsigned data only if an insecure delegation between
				// zone and qname is cryptographically proven.
				if !r.provenInsecureDelegation(ctx, zone, q.Name, parentDS) {
					zlog.Warn("DNSSEC verify failed (answer)", "query", dnsutil.FormatQuestion(q), "error", dnssec.ErrNoSignatures.Error())
					return nil, dnssec.ErrNoSignatures
				}
			}
		} else {
			origDSRR := parentDS
			var lastErr error
			settled := false
			for _, signer := range signers {
				if err := dnssec.ValidateSigner(signer, q.Name); err != nil {
					lastErr = err
					continue
				}
				candidateDSRR, err := r.findDS(ctx, signer, q.Name, origDSRR, false)
				if err != nil {
					if isDNSSECWorkError(err) {
						return nil, err
					}
					lastErr = err
					continue
				}
				if len(candidateDSRR) == 0 {
					if r.isZoneSecure(ctx, q.Name, origDSRR, zone) {
						lastErr = dnssec.ErrDSRecords
						continue
					}
					// Genuinely insecure for this candidate; accept
					// without AD and stop trying alternates.
					settled = true
					break
				}
				ok, verr := r.verifyDNSSEC(ctx, signer, strings.ToLower(q.Name), resp, candidateDSRR)
				if verr != nil {
					if isDNSSECWorkError(verr) {
						return nil, verr
					}
					lastErr = verr
					continue
				}
				if ok {
					// VerifyRRSIG tolerates out-of-zone authority
					// records (referral remnants for a CNAME target)
					// by excluding them from validation. Drop them
					// here so the AD bit never covers unvalidated
					// data (RFC 4035 §3.2.3); the CNAME chase
					// re-resolves the target through its own
					// validated recursion anyway.
					resp.Ns = dnsutil.FilterRRsToZone(resp.Ns, signer)

					// RFC 4035 §5.3.4: a wildcard-expanded answer is only
					// authentic if the response also proves the owner name
					// has no closer match than the wildcard. Otherwise a
					// zone's legitimately-signed wildcard RRSIG can be
					// replayed over a concrete name that really exists and
					// returned with AD=1. The NSEC/NSEC3 proof consulted
					// here was validated by verifyDNSSEC above.
					wildcardSecure, werr := dnssec.VerifyWildcardAnswerForZoneWithWork(
						resp,
						signer,
						r.dnssecWork(ctx),
					)
					if werr != nil {
						zlog.Warn("DNSSEC verify failed (wildcard answer)", "query", dnsutil.FormatQuestion(q), "error", werr.Error())
						return nil, werr
					}
					ok = wildcardSecure
				}
				resp.AuthenticatedData = ok
				settled = true
				break
			}
			if !settled {
				if lastErr == nil {
					lastErr = dnssec.ErrNoSignatures
				}
				zlog.Warn("DNSSEC verify failed (answer)", "query", dnsutil.FormatQuestion(q), "error", lastErr.Error())
				return nil, lastErr
			}
		}
	}

	if targetMsg != nil {
		// Splice the target response into resp *after* DNSSEC check.
		// The internal recursion already validated the target zone
		// and set msg.AuthenticatedData accordingly; AND it into the
		// outer AD so the combined response is authentic only if
		// both sides are.
		if targetCut != nil {
			// The target's records are part of the client's answer now, so
			// the outer response inherits how long they may be served.
			deadline, key := targetCut.Cut()
			middleware.ResponseMetaFrom(ctx).BoundCutFor(deadline, key)
		}
		resp.Answer = append(resp.Answer, targetMsg.Answer...)
		resp.Rcode = targetMsg.Rcode
		terminalDenial := targetMsg.Rcode == dns.RcodeNameError
		if !req.CheckingDisabled {
			resp.AuthenticatedData = resp.AuthenticatedData && targetMsg.AuthenticatedData
		}
		if terminalDenial {
			middleware.PropagateValidatedDenialResponse(ctx, targetMsg, resp)
			// RFC 6672 §5.3.4: carry only the target zone's SOA and
			// NSEC/NSEC3 proof. clearAdditional removes any outer-zone
			// authority/additional remnants first; restoring the target
			// proof afterward prevents it from being wiped with them.
			targetAuthority := append([]dns.RR(nil), targetMsg.Ns...)
			resp = r.clearAdditional(req, resp, extra...)
			resp.Ns = targetAuthority
			return resp, nil
		}
		negative, markedNegative := middleware.ValidatedNegativeProofForResponse(ctx, targetMsg)
		terminalNODATA := markedNegative &&
			negative.Proof != nil &&
			negative.Proof.Rcode == dns.RcodeSuccess &&
			len(negative.Proof.Answer) == 0
		if terminalNODATA || len(targetMsg.Answer) == 0 {
			// Preserve the historical NODATA handling: its target authority
			// proof must survive the generic additional-section cleanup. A
			// target may itself contain an alias chain; the exact terminal
			// proof marker, not targetMsg.Answer length, identifies that case.
			if terminalNODATA {
				middleware.PropagateValidatedNegativeProofResponse(ctx, targetMsg, resp)
			}
			resp.Ns = append(resp.Ns, targetMsg.Ns...)
			return resp, nil
		}
	}

	resp = r.clearAdditional(req, resp, extra...)

	return resp, nil
}

func (r *Resolver) authority(ctx context.Context, req, resp *dns.Msg, parentDS []dns.RR, zone string) (*dns.Msg, error) {
	if req == nil || resp == nil || len(req.Question) != 1 ||
		len(resp.Question) != 1 ||
		req.Question[0].Qtype != resp.Question[0].Qtype ||
		req.Question[0].Qclass != resp.Question[0].Qclass ||
		dns.CanonicalName(req.Question[0].Name) != dns.CanonicalName(resp.Question[0].Name) {
		// Bind semantic denial validation to the question we actually sent.
		// The transport already rejects mismatched echoes; keeping the same
		// invariant at this trust seam prevents a future/custom exchange path
		// from validating one absent name and attributing its RFC 8020 cut to
		// another.
		return nil, ErrQuestion
	}

	if !req.CheckingDisabled {
		if r.dnssec && !r.hasTrustAnchors() {
			return nil, dnssec.ErrTrustAnchorsUnavailable
		}
		q := req.Question[0]

		signers := r.findRRSIGSigners(resp, q.Name, false)
		if len(signers) == 0 {
			if r.isZoneSecure(ctx, q.Name, parentDS, zone) {
				// As in answer(): a negative response with no proof is
				// only acceptable when qname sits under a proven insecure
				// delegation below the signed zone we queried (the same
				// shared-authority, no-referral case).
				if !r.provenInsecureDelegation(ctx, zone, q.Name, parentDS) {
					err := dnssec.ErrNoSignatures
					zlog.Warn("DNSSEC verify failed (NXDOMAIN)", "query", dnsutil.FormatQuestion(q), "error", err.Error())
					return nil, err
				}
			}
		} else {
			origDSRR := parentDS
			var (
				lastErr      error
				settled      bool
				verified     bool
				chosenSigner string
			)
			for _, signer := range signers {
				if err := dnssec.ValidateSigner(signer, q.Name); err != nil {
					lastErr = err
					continue
				}
				candidateDSRR, err := r.findDS(ctx, signer, q.Name, origDSRR, false)
				if err != nil {
					if isDNSSECWorkError(err) {
						return nil, err
					}
					lastErr = err
					continue
				}
				if len(candidateDSRR) == 0 {
					if r.isZoneSecure(ctx, q.Name, origDSRR, zone) {
						lastErr = dnssec.ErrDSRecords
						continue
					}
					// Insecure — accept without AD, stop trying alternates.
					settled = true
					break
				}
				ok, verr := r.verifyDNSSEC(ctx, signer, q.Name, resp, candidateDSRR)
				if verr != nil {
					if isDNSSECWorkError(verr) {
						return nil, verr
					}
					lastErr = verr
					continue
				}
				verified = ok
				chosenSigner = signer
				settled = true
				break
			}
			if !settled {
				if lastErr == nil {
					lastErr = dnssec.ErrNoSignatures
				}
				zlog.Warn("DNSSEC verify failed (NXDOMAIN)", "query", dnsutil.FormatQuestion(q), "error", lastErr.Error())
				return nil, lastErr
			}

			if r.dnssec && verified {
				// Require denial-of-existence proof for every
				// negative response under a signed zone. Without
				// it, a forged SOA+RRSIG would be enough to set
				// the AD bit, since verifyDNSSEC only proves the
				// authority section is signed — not that the
				// queried name/type really doesn't exist.
				//
				// Filter NSEC/NSEC3 records to the validated signer
				// zone: dnssec.VerifyRRSIG only checked signatures for in-
				// zone records, so out-of-zone NSECs could otherwise
				// satisfy canonical-coverage checks here without
				// having been cryptographically authenticated.
				nsec3Set := dnsutil.FilterRRsToZone(dnsutil.ExtractRRSet(resp.Ns, "", dns.TypeNSEC3), chosenSigner)
				nsecSet := dnsutil.FilterRRsToZone(dnsutil.ExtractRRSet(resp.Ns, "", dns.TypeNSEC), chosenSigner)
				isNegative := resp.Rcode == dns.RcodeNameError ||
					(resp.Rcode == dns.RcodeSuccess && len(resp.Answer) == 0)
				proofKind := middleware.ValidatedNegativeProofUnknown
				aggressiveEligible := false
				denialSecure := true
				var denialErr error
				proofQuestion := q
				if dnameTarget := dnsutil.DnameTarget(resp); dnameTarget != "" {
					proofQuestion.Name = dnameTarget
				}

				if isNegative {
					switch {
					case len(nsec3Set) > 0:
						proofKind = middleware.ValidatedNegativeProofNSEC3
						if resp.Rcode == dns.RcodeNameError {
							denialSecure, denialErr = dnssec.VerifyNameErrorForZoneWithWork(
								resp,
								nsec3Set,
								chosenSigner,
								r.dnssecWork(ctx),
							)
							if denialErr != nil {
								zlog.Warn("NSEC3 verify failed (NXDOMAIN)", "query", dnsutil.FormatQuestion(q), "error", denialErr.Error())
								return nil, denialErr
							}
						} else {
							denialSecure, denialErr = dnssec.VerifyNODATAForZoneWithWork(
								resp,
								nsec3Set,
								chosenSigner,
								r.dnssecWork(ctx),
							)
							if denialErr != nil {
								zlog.Warn("NSEC3 verify failed (NODATA)", "query", dnsutil.FormatQuestion(q), "error", denialErr.Error())
								return nil, denialErr
							}
						}

						if denialSecure {
							result, err := dnssec.EvaluateAggressiveNSEC3(
								proofQuestion,
								chosenSigner,
								nsec3Set,
								newResolverAggressiveProofWork(ctx, r.cryptoLimiter),
							)
							if err == nil && result.Rcode == resp.Rcode {
								aggressiveEligible = true
							} else {
								// Exact-response validation above remains
								// authoritative. RFC 8198 reuse is stricter,
								// so any evaluator miss only withholds shared
								// provenance.
								zlog.Debug("NSEC3 proof not eligible for aggressive reuse",
									"query", dnsutil.FormatQuestion(q), "error", err, "classified_rcode", result.Rcode)
							}
						}
					case len(nsecSet) > 0:
						proofKind = middleware.ValidatedNegativeProofNSEC
						if resp.Rcode == dns.RcodeNameError {
							if err := dnssec.VerifyNameErrorNSEC(resp, nsecSet); err != nil {
								zlog.Warn("NSEC verify failed (NXDOMAIN)", "query", dnsutil.FormatQuestion(q), "error", err.Error())
								return nil, err
							}
						} else {
							if err := dnssec.VerifyNODATANSEC(resp, nsecSet); err != nil {
								zlog.Warn("NSEC verify failed (NODATA)", "query", dnsutil.FormatQuestion(q), "error", err.Error())
								return nil, err
							}
						}

						result, err := dnssec.EvaluateAggressiveNSEC(proofQuestion, chosenSigner, nsecSet)
						if err == nil && result.Rcode == resp.Rcode {
							aggressiveEligible = true
						} else {
							zlog.Debug("NSEC proof not eligible for aggressive reuse",
								"query", dnsutil.FormatQuestion(q), "error", err, "classified_rcode", result.Rcode)
						}
					default:
						zlog.Warn("Negative answer missing NSEC/NSEC3 denial proof", "query", dnsutil.FormatQuestion(q), "rcode", dns.RcodeToString[resp.Rcode])
						return nil, dnssec.ErrNSECMissingCoverage
					}
				}

				if !req.CheckingDisabled {
					resp.AuthenticatedData = denialSecure
				}
				if !req.CheckingDisabled && denialSecure && isNegative &&
					proofKind != middleware.ValidatedNegativeProofUnknown {
					middleware.MarkValidatedNegativeProofResponse(ctx, resp, middleware.ValidatedNegativeProof{
						Subject:    proofQuestion.Name,
						Zone:       chosenSigner,
						Kind:       proofKind,
						Aggressive: aggressiveEligible,
					})
				}
			}
		}
	}

	return resp, nil
}

func (r *Resolver) lookup(ctx context.Context, rs *resolveState, req *dns.Msg, servers *authority.Servers) (resp *dns.Msg, err error) {
	var serversList []*authority.Server

	servers.RLock()
	serversList = append(serversList, servers.List...)
	level := dns.CountLabel(servers.Zone)
	servers.RUnlock()

	// probing is the server the second slot is spending on an exploration
	// probe, if it is spending it on one. It is carried as the server
	// rather than the position because dedupe runs next and can move it.
	probing := authority.Sort(serversList) // fastest first
	serversList = dedupeAuthorityServers(serversList)

	responseErrors := []*dns.Msg{}
	configErrors := []*dns.Msg{}
	fatalErrors := []error{}

	// Single unbuffered channel. Stragglers whose result arrives after
	// lookup has picked a winner drop their send via ctx.Done() — the
	// WithCancel ctx below is the cancellation signal, so we don't
	// need a separate "returned" channel.
	results := make(chan lookupResult)

	originalID := req.Id // Capture ID before goroutines start

	// Start the timer for the fallback racer.
	fallbackTimer := time.NewTimer(150 * time.Millisecond)
	defer fallbackTimer.Stop()

	left := len(serversList)

	ctx, cancel := context.WithCancel(ctx)
	// One cancellation registration for every exchange this lookup fans
	// out, instead of a context.AfterFunc per upstream attempt. Deferred
	// before cancel so cancel runs first (LIFO): the exit cancellation
	// still interrupts straggler reads through the group, and only then
	// is the registration detached.
	interrupts := NewInterruptGroup(ctx)
	defer interrupts.Close()
	defer cancel()

	// Start queries to top 2 servers immediately for faster response
	parallelStart := 2
	if len(serversList) < parallelStart {
		parallelStart = len(serversList)
	}

mainloop:
	for index, server := range serversList {
		// Check if we're approaching the limit and log a warning
		activeQueries := len(r.maxConcurrent)
		maxQueries := cap(r.maxConcurrent)
		if activeQueries > maxQueries*9/10 { // Over 90% capacity
			zlog.Warn("Approaching max concurrent DNS queries limit",
				"active", activeQueries, "max", maxQueries,
				"query", dnsutil.FormatQuestion(req.Question[0]))
		}

		// A pooled per-attempt view of the leader request: own slice
		// backings, shared records. Built serially so every attempt reads
		// the leader before anything downstream could touch it.
		serverReq := acquireAttemptReq(req)

		// Acquire semaphore slot before starting goroutine
		select {
		case r.maxConcurrent <- struct{}{}:
			// Got a slot, start the query
			go r.queryServer(ctx, rs, interrupts, originalID, serverReq, server, results, server == probing)
		case <-ctx.Done():
			// Context cancelled while waiting for slot —
			// return the pre-copied pooled message before
			// exiting so overload/timeout paths don't leak
			// pooled dns.Msg buffers.
			ReleaseMsg(serverReq)
			return nil, ctx.Err()
		}

		// For the first 3 servers, don't wait - query them in parallel
		if index < parallelStart-1 {
			continue
		}

		// Use adaptive timeout for subsequent servers
		fallbackTimeout := adaptiveServerTimeout(server)

	fallbackloop:
		for left != 0 {
			fallbackTimer.Reset(fallbackTimeout)

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-fallbackTimer.C:
				if left > 0 && len(serversList)-1 == index {
					continue fallbackloop
				}
				continue mainloop
			case res := <-results:
				left--

				if res.err != nil {
					// A request-tree work rejection is terminal policy,
					// not an authority failure. Trying another server
					// would only repeat the rejected operation and can
					// hide the policy EDE behind a fallback response.
					if errors.Is(res.err, middleware.ErrRecursionWorkLimit) {
						return nil, res.err
					}
					fatalErrors = append(fatalErrors, res.err)

					if left > 0 && len(serversList)-1 == index {
						continue fallbackloop
					}
					continue mainloop
				}

				resp = res.resp

				if resp.Rcode != dns.RcodeSuccess {
					responseErrors = append(responseErrors, resp)

					// we don't need to look all nameservers for that response
					// we trust name errors if return from root servers
					if (len(responseErrors) > 2 || level < 2) && resp.Rcode == dns.RcodeNameError {
						break mainloop
					}

					if left > 0 && len(serversList)-1 == index {
						continue fallbackloop
					}
					continue mainloop
				}

				if resp.Rcode == dns.RcodeSuccess && len(resp.Ns) > 0 && len(resp.Answer) == 0 {
					info := r.extractDelegationInfo(resp)
					if info.nsRecord != nil && !validReferral(info, servers.Zone, req.Question[0]) {
						configErrors = append(configErrors, resp)

						// Penalise the server that actually produced this
						// bogus delegation, not the current loop index —
						// results arrive out of order from parallel
						// goroutines, so `server` can be a later peer.
						// It replied, but with a delegation it had no
						// business sending, which is not an answer to the
						// question we asked.
						res.server.ObserveNoAnswer(2 * time.Second)

						if left > 0 && len(serversList)-1 == index {
							continue fallbackloop
						}
						continue mainloop
					}
				}

				return resp, nil
			}
		}
	}

	return pickFallbackResponse(responseErrors, configErrors, fatalErrors)
}

// linearDedupeLimit is the list size below which duplicate suppression
// compares rather than indexes. A delegation names a handful of servers — the
// root names thirteen — so the quadratic scan is a few dozen comparisons of
// values already in registers, against a map that has to be built, sized and
// discarded on every lookup.
const linearDedupeLimit = 24

func dedupeAuthorityServers(servers []*authority.Server) []*authority.Server {
	if len(servers) <= linearDedupeLimit {
		return dedupeAuthorityServersLinear(servers)
	}
	return dedupeAuthorityServersIndexed(servers)
}

// dedupeAuthorityServersLinear suppresses duplicates by comparing each server
// against the ones already kept, in place and without allocating.
//
// The addresses arrive decoded — Endpoint is the value the constructor built
// Addr from — so identity is a comparison of two netip.AddrPorts. Only a
// server whose address is not an IP:port literal needs its spelling
// canonicalized, and those never reach this path from the delegation
// producers.
func dedupeAuthorityServersLinear(servers []*authority.Server) []*authority.Server {
	result := servers[:0]
	for _, server := range servers {
		if server == nil {
			continue
		}
		duplicate := false
		for _, kept := range result {
			if sameResolutionEndpoint(kept, server) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			result = append(result, server)
		}
	}
	return result
}

func dedupeAuthorityServersIndexed(servers []*authority.Server) []*authority.Server {
	seen := make(map[string]struct{}, len(servers))
	result := servers[:0]
	for _, server := range servers {
		if server == nil {
			continue
		}
		key := resolutionEndpointIdentity(server)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, server)
	}
	return result
}

// resolutionEndpointIdentity returns the spelling that identifies a server's
// upstream. A server built from a decoded address already holds it; anything
// else has to be normalized, and normalization is what produces a string.
func resolutionEndpointIdentity(server *authority.Server) string {
	if addr, canonical := server.CanonicalAddr(); canonical {
		return addr
	}
	return middleware.CanonicalResolutionEndpoint(server.Addr)
}

// sameResolutionEndpoint reports whether two servers name the same upstream.
// Two canonical spellings compare directly; anything else is normalized
// first, which only the servers whose address never was a literal reach.
func sameResolutionEndpoint(a, b *authority.Server) bool {
	aAddr, aCanonical := a.CanonicalAddr()
	bAddr, bCanonical := b.CanonicalAddr()
	if aCanonical && bCanonical {
		return aAddr == bAddr
	}
	return resolutionEndpointIdentity(a) == resolutionEndpointIdentity(b)
}

// lookupResult bundles a single per-server query outcome for the
// fan-out loop in (*Resolver).lookup.
type lookupResult struct {
	resp   *dns.Msg
	err    error
	server *authority.Server
}

// queryServer issues one UDP exchange to server and ships the outcome on
// results. It owns the semaphore slot the caller acquired before
// launching the goroutine, and the pooled reqCopy buffer; both are
// released before the result send so the main loop can keep launching
// workers while we queue.
// probeMode marks an attempt as a measurement probe, and rides on the
// probe's own detached context — the one thing already scoped to a single
// attempt, so it cannot reach another one. What it turns off is the retry
// and the fallbacks to TCP: those exist to get an answer, and a probe's
// answer has no reader once the lookup it was born in has returned. One
// exchange is what a probe is for, and one exchange is what it costs.
type probeMode struct{}

func withProbeMode(ctx context.Context) context.Context {
	return context.WithValue(ctx, probeMode{}, true)
}

func isProbe(ctx context.Context) bool {
	on, _ := ctx.Value(probeMode{}).(bool)
	return on
}

// retainForProbe holds the request tree's work ledger open across an
// attempt that outlives the lookup, the same way the detached IPv6
// enrichment holds it. Detaching the context carries the ledger through
// but does not keep it alive: once the tree completes, a debit against it
// comes back as an error, and this path would read that as the authority
// failing and trip its circuit breaker for the resolver's own bookkeeping.
//
// It reports false when the tree is already finished, which is when
// starting detached work would escape the tree's aggregate cap.
func retainForProbe(rs *resolveState) (release func(), ok bool) {
	if rs == nil || rs.work == nil {
		return func() {}, true
	}
	return rs.work.Retain()
}

// queryServer runs one upstream attempt and reports it back to lookup.
//
// probing marks the attempt the ranking chose to spend on a server whose
// worth is out of date. It is the same query as any other, but what it is
// worth is the opposite: an ordinary attempt is worth the answer it may
// bring and nothing once the leader has answered, while a probe is worth
// only the measurement, and there is no measurement until the server
// replies. Cancelling it the moment the leader answers — which is what
// happens to every other attempt — cancels it before it can say anything,
// every time, because the leader is by construction the fastest server in
// the list. Exploring at any rate then measures only the addresses quick
// enough to win outright, which on a production delegation was one new
// address a minute against seventeen waiting.
//
// So a probe runs on a context detached from the lookup's. The query
// itself is one that was being sent anyway.
func (r *Resolver) queryServer(ctx context.Context, rs *resolveState, interrupts *InterruptGroup, originalID uint16, reqCopy *dns.Msg, server *authority.Server, results chan<- lookupResult, probing bool) {
	defer ReleaseMsg(reqCopy)

	// exchangeCtx is what the attempt runs under; ctx stays the lookup's,
	// because the result is only wanted while the lookup is still there to
	// read it.
	exchangeCtx := ctx
	if probing {
		if releaseWork, retained := retainForProbe(rs); retained {
			select {
			case r.probeSlots <- struct{}{}:
				defer func() { <-r.probeSlots }()
				defer releaseWork()

				// Detached, so the winner's cancellation does not reach it.
				// Values are carried through, so the request tree still
				// meters this query as its own — and the retain above is
				// what keeps that ledger open long enough to be metered
				// against.
				//
				// The deadline is one exchange window and a grace. The
				// grace is there so the socket deadline is what ends a
				// silent server, which is the difference between recording
				// a failure and recording nothing. A probe therefore lives
				// no longer than any other attempt.
				var release context.CancelFunc
				exchangeCtx, release = context.WithTimeout(context.WithoutCancel(ctx), r.netTimeout+probeGrace)
				defer release()
				exchangeCtx = withProbeMode(exchangeCtx)

				// The interrupt group belongs to the lookup and fires with
				// it, so a probe registered there would be cut down anyway.
				// Nil leaves the exchange on its own context, which is the
				// detached one.
				interrupts = nil
			default:
				// The probe pool is full. Shedding a measurement is free,
				// and the attempt goes ahead as the hedge it would have
				// been: exchangeCtx is still the lookup's, so the winner
				// cancels it like any other.
				releaseWork()
			}
		}
	}

	// releaseSlot frees the semaphore slot acquired by the main
	// loop before this goroutine was launched. We must release
	// before a blocking send on results (or before returning
	// without a send), otherwise a small MaxConcurrentQueries
	// setting deadlocks the lookup: the main loop blocks trying
	// to acquire a slot for the next server while this worker
	// holds its own slot blocked on a send the main loop never
	// reaches.
	slotReleased := false
	releaseSlot := func() {
		if !slotReleased {
			<-r.maxConcurrent
			slotReleased = true
		}
	}
	defer releaseSlot()

	res := lookupResult{server: server}

	switch {
	case !r.circuitBreaker.canQuery(server.Addr):
		res.err = fatalError(errConnectionFailed)
	case contextutil.EffectiveError(exchangeCtx) != nil:
		// The context this attempt would run under, which for a probe is
		// not the lookup's. Reading the lookup's here undid the admission
		// that had just been granted: a probe took a slot and retained the
		// ledger, and then returned without reaching the wire because a
		// fast leader had cancelled in the meantime — which is precisely
		// the case it exists for.
		return
	default:
		reqCopy.Id = dns.Id() // anti-spoofing
		resp, err := r.exchange(exchangeCtx, rs, interrupts, "udp", reqCopy, server, 0)
		if resp != nil {
			resp.Id = originalID
		}
		switch {
		case errors.Is(err, middleware.ErrRecursionWorkLimit),
			errors.Is(err, middleware.ErrResolutionAttemptLimit),
			errors.Is(err, middleware.ErrFailureProbeLimit),
			errors.Is(err, middleware.ErrMaxRecursion),
			// The context the attempt ran under, which for a probe is not
			// the lookup's: by the time a probe finishes the lookup has
			// usually returned and cancelled its own, and reading that one
			// would throw away the health evidence the probe went to get.
			contextutil.EffectiveError(exchangeCtx) != nil:
			// Local policy exhaustion says nothing about the
			// authority's health; neither does cancellation of this request
			// tree. Do not use errors.Is(err, context.DeadlineExceeded) here:
			// a per-socket or Dialer timeout may wrap that sentinel while the
			// request context itself is still live, and that is genuine
			// upstream health evidence.
		case err != nil:
			r.circuitBreaker.recordFailure(server.Addr)
		case resp != nil:
			// Any response from the authority — NOERROR,
			// NXDOMAIN, NODATA — proves the server is
			// reachable and answering, so reset the failure
			// streak. Scoping recovery to RcodeSuccess only
			// leaves healthy servers tripped when they keep
			// (correctly) returning negative answers
			// interleaved with transient timeouts.
			r.circuitBreaker.recordSuccess(server.Addr)
		}
		res.resp = resp
		res.err = err
	}

	// Release before the send so the main loop can keep
	// launching workers while we queue the result.
	releaseSlot()
	select {
	case results <- res:
	case <-ctx.Done():
	}
}

// answeredTheQuestion reports the rcodes that mean the authority did the
// job it was asked to do: the name exists and here it is, the name does
// not exist, or — RFC 6672 §2.2, a DNAME substitution that would exceed
// 255 octets — the question can have no answer at all. Everything else is
// a server that did not answer, however quickly it said so.
//
// A list of what counts rather than a list of what does not, because the
// failure mode is asymmetric: a rcode nobody thought about lands in the
// default, and the safe default is "this did not answer my question".
func answeredTheQuestion(rcode int) bool {
	return rcode == dns.RcodeSuccess ||
		rcode == dns.RcodeNameError ||
		rcode == dns.RcodeYXDomain
}

// adaptiveServerTimeout picks how long lookup waits on a single server
// before racing the next candidate. With no RTT samples the result is a
// conservative 100ms; otherwise it is 2× the observed RTT clamped to
// [25ms, 300ms] so a single slow outlier can't stall the whole fan-out.
func adaptiveServerTimeout(server *authority.Server) time.Duration {
	rtt := server.SmoothedRTT()
	if rtt <= 0 {
		return 100 * time.Millisecond
	}
	timeout := rtt * 2
	switch {
	case timeout < 25*time.Millisecond:
		return 25 * time.Millisecond
	case timeout > 300*time.Millisecond:
		return 300 * time.Millisecond
	default:
		return timeout
	}
}

// pickFallbackResponse selects what to return when the lookup loop
// exhausts every authority without a clean success: prefer NXDOMAIN over
// other rcodes, then any negative response, then the bogus-delegation
// list, then a connection error, then the absolute-last-resort no-roots
// fatal.
func pickFallbackResponse(responseErrors, configErrors []*dns.Msg, fatalErrors []error) (*dns.Msg, error) {
	// Policy exhaustion is terminal even if an earlier authority supplied a
	// fallback response. Returning that response would conceal the enforced
	// request-tree limit and let caller retry paths continue doing work.
	for _, err := range fatalErrors {
		if errors.Is(err, middleware.ErrRecursionWorkLimit) {
			return nil, err
		}
	}

	for _, resp := range responseErrors {
		if resp.Rcode == dns.RcodeNameError {
			return resp, nil
		}
	}
	for _, err := range fatalErrors {
		if errors.Is(err, middleware.ErrResolutionAttemptLimit) {
			return nil, err
		}
	}
	if len(responseErrors) > 0 {
		return responseErrors[0], nil
	}
	if len(configErrors) > 0 {
		return configErrors[0], nil
	}
	if len(fatalErrors) > 0 {
		return nil, fatalError(errConnectionFailed)
	}
	zlog.Fatal("Looks like no root servers, check your config")
	return nil, fatalError(errNoRootServers)
}

func (r *Resolver) exchange(ctx context.Context, rs *resolveState, interrupts *InterruptGroup, proto string, req *dns.Msg, server *authority.Server, retried int) (*dns.Msg, error) {
	if ctxErr := contextutil.EffectiveError(ctx); ctxErr != nil {
		return nil, ctxErr
	}
	q := req.Question[0]
	// Addr was printed from a decoded address at construction, so it is
	// already the canonical spelling the guard keys on; normalizing it
	// again would parse that string and print an identical one back.
	// A server whose address never was a literal has no such promise.
	attemptErr := error(nil)
	if addr, canonical := server.CanonicalAddr(); canonical {
		attemptErr = middleware.BeginResolutionAttemptCanonical(ctx, q, addr, proto)
	} else {
		attemptErr = middleware.BeginResolutionAttempt(ctx, q, server.Addr, proto)
	}
	if attemptErr != nil {
		return nil, attemptErr
	}
	if rs.work != nil {
		var err error
		if middleware.IsBestEffortRecursionWork(ctx) {
			err = rs.work.DebitBestEffort(middleware.RecursionWorkOutboundQuery)
		} else {
			err = rs.work.Debit(middleware.RecursionWorkOutboundQuery)
		}
		if err != nil {
			return nil, err
		}
	}

	var resp *dns.Msg
	var err error

	// Track RTT for adaptive timeouts
	var rtt = r.netTimeout

	// record files this attempt's outcome with the ranking, once.
	//
	// It is called explicitly before this frame hands its work to a retry
	// or a fallback, because those recurse: the frame that answered
	// returns before the frame that failed, so leaving both to the defer
	// delivered them backwards. A server that timed out and then answered
	// on the retry had the timeout recorded last, and a blend that halves
	// with each sample put it near the timeout — a server that had just
	// answered, priced as one that had not.
	observed := false
	record := func() {
		if observed {
			return
		}
		if contextutil.EffectiveError(ctx) != nil {
			// This attempt was cancelled because a peer answered first.
			// What it took to get cancelled is not what this server is
			// worth, and recording it would make a server nobody has heard
			// from look like the fastest in the delegation.
			return
		}
		observed = true
		switch {
		case err != nil || resp == nil:
			// Nothing came back. Only an answer is worth what it took, and
			// the ways of not answering are fast for the wrong reason: a
			// refused connection comes back in microseconds, quicker than
			// any authority on earth. The exchange reports elapsed time
			// whatever the outcome, so scoring these by the clock made the
			// one address in a delegation that serves nothing into its
			// permanent leader. Not answering is worth a timeout.
			server.ObserveNoAnswer(r.netTimeout)

		case answeredTheQuestion(resp.Rcode):
			server.Observe(rtt)

		case isProbe(ctx) && resp.Rcode == dns.RcodeFormatError:
			// The one rcode a probe reads differently. It says the server
			// dislikes the shape of our query, not that it failed to
			// answer — the lookup path replies to it by asking again
			// without EDNS, and prices the attempt at nothing. A probe
			// cannot price it at nothing: recording nothing leaves the
			// address as out of date as it was, so it is a candidate
			// again, so it is probed again, for as long as the server
			// keeps saying it. The round trip is what a probe went to find
			// out, and this server did make one.
			server.Observe(rtt)

		default:
			server.ObserveNoAnswer(r.netTimeout)
		}
	}
	defer record()

	// Check if we should use TCP connection pooling
	var pooledConn *dns.Conn
	var isRoot, isTLD bool

	if proto == "tcp" && r.tcpPool != nil && r.cfg.TCPKeepalive {
		// Check if this is a root or TLD server
		isRoot = isRootServer(server.Addr)
		if !isRoot && len(req.Question) > 0 {
			isTLD = isTLDServer(req.Question[0].Name)
		}

		// Try to get a pooled connection
		if isRoot || isTLD {
			pooledConn = r.tcpPool.Get(server.Addr, isRoot, isTLD)
			if pooledConn != nil {
				zlog.Debug("Using pooled TCP connection", "server", server.Addr, "isRoot", isRoot, "isTLD", isTLD)
			}
		}
	}

	co := AcquireConn()

	// Dial target. In production resolveTarget is nil, so dialAddr == the
	// server's own address and the UDP fast path below is unchanged. A test
	// mapper can redirect an advertised address (e.g. TEST-NET-1 glue) to a
	// loopback listener; when it remaps, we take the string-dial path so the
	// remapped address is honoured instead of the pre-parsed UDPAddr.
	dialAddr := server.Addr
	if m := r.resolveTarget.Load(); m != nil {
		dialAddr = (*m)(server.Addr)
	}

	switch {
	case pooledConn != nil:
		// Use the pooled TCP connection.
		co.Conn = pooledConn.Conn
	case proto == "udp" && server.UDPAddr != nil && dialAddr == server.Addr:
		// Fast UDP path: net.DialUDP with pre-parsed addresses skips
		// DialContext's resolveAddrList + dialParallel + internal
		// context.WithDeadline, which together account for most of
		// the allocation noise on every upstream query.
		co.Conn, err = r.dialUDP(server)
		if err != nil {
			zlog.Debug("Dial failed to upstream server", "query", dnsutil.FormatQuestion(q), "upstream", server.Addr,
				"net", proto, "error", err.Error(), "retried", retried)
			ReleaseConn(co)
			return nil, err
		}
	default:
		// TCP / fallback path: use the full Dialer machinery.
		d := r.newDialer(ctx, rs, proto, server.IPVersion)
		co.Conn, err = d.DialContext(ctx, proto, dialAddr)
		releaseDialer(d)
		if err != nil {
			zlog.Debug("Dial failed to upstream server", "query", dnsutil.FormatQuestion(q), "upstream", server.Addr,
				"net", proto, "error", err.Error(), "retried", retried)
			ReleaseConn(co)
			return nil, err
		}
	}

	// Add EDNS-Keepalive option if using TCP pooling
	if proto == "tcp" && r.tcpPool != nil && r.cfg.TCPKeepalive && (isRoot || isTLD) {
		// The attempt shares the leader's OPT; the keepalive append below
		// is the one OPT write on this path, so it pays for a private OPT
		// here, on the rare TCP leg.
		privatizeOPT(req)
		SetEDNSKeepalive(req, 0) // Request keepalive with no specific timeout
	}

	// Set deadline respecting both network timeout and context deadline
	deadline := time.Now().Add(r.netTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = co.SetDeadline(deadline)

	resp, rtt, err = co.ExchangeInterruptible(ctx, interrupts, req)
	if ctxErr := contextutil.EffectiveError(ctx); ctxErr != nil {
		resp = nil
		err = ctxErr
	}
	if err != nil {
		zlog.Debug("Exchange failed for upstream server", "query", dnsutil.FormatQuestion(q), "upstream", server.Addr,
			"net", proto, "rtt", rtt.Round(time.Millisecond).String(), "error", err.Error(), "retried", retried)

		// Don't return connection to pool on error
		ReleaseConn(co)

		if contextutil.EffectiveError(ctx) != nil {
			return nil, err
		}
		if retried < 2 && !isProbe(ctx) {
			if retried == 1 && proto == "udp" {
				proto = "tcp"
			}
			// retry
			retried++
			record()
			return r.exchange(ctx, rs, interrupts, proto, req, server, retried)
		}

		return nil, err
	}

	// Handle connection pooling
	if proto == "tcp" && r.tcpPool != nil && r.cfg.TCPKeepalive && (isRoot || isTLD) {
		// Return connection to pool
		dnsConn := &dns.Conn{Conn: co.Conn, UDPSize: co.UDPSize}
		r.tcpPool.Put(dnsConn, server.Addr, isRoot, isTLD, resp)
		// Don't close the connection since it's pooled
		co.Conn = nil
	}

	ReleaseConn(co)

	// A probe stops here on both of these, and what it records is the UDP
	// round trip it completed — deliberately, not by omission. The
	// fallbacks exist to get an answer, and by the time a probe has one
	// the lookup it was born in has returned and nobody is left to read
	// it.
	//
	// That does understate an authority whose TCP is slow or broken:
	// truncation sends the real lookup to TCP, and the probe's number
	// covers only the UDP leg. The alternative is worse. Pricing a
	// truncated reply as a failure would mark a server that answered
	// promptly and correctly, and truncation is a property of the answer's
	// size rather than of the server, so it would fall on whichever
	// addresses happened to be probed with a large question. A server
	// whose TCP is genuinely broken is caught where the evidence actually
	// exists: the first real lookup that needs TCP records a failure
	// against it, and the estimate halves toward the timeout at once.
	if resp != nil && resp.Truncated && proto == "udp" && !isProbe(ctx) {
		record()
		return r.exchange(ctx, rs, interrupts, "tcp", req, server, retried)
	}

	if resp != nil && !resp.Truncated && proto == "udp" && resp.Len() > dnsutil.DefaultMsgSize && !isProbe(ctx) {
		// If response is too large, switch to TCP
		zlog.Debug("Response too large, switching to TCP", "query", dnsutil.FormatQuestion(q), "upstream", server.Addr,
			"size", resp.Len(), "maxSize", dnsutil.DefaultMsgSize, "retried", retried)
		record()
		return r.exchange(ctx, rs, interrupts, "tcp", req, server, retried)
	}

	if resp != nil && resp.Rcode == dns.RcodeFormatError && req.IsEdns0() != nil {
		if isProbe(ctx) {
			// A probe stops here, and it has to leave a measurement behind.
			// Recording nothing left the address exactly as it was — out of
			// date, so a candidate again, so probed again, for as long as
			// the server keeps refusing our EDNS. The round trip is what a
			// probe went to find out and the server did make it; that it
			// dislikes the shape of the query is a fact about the query.
			return resp, nil
		}
		// A server that cannot parse EDNS is not a server that failed to
		// answer: this attempt is being replaced, not scored. Marking it
		// observed keeps the defer from pricing our own choice of query
		// shape as the authority's fault.
		observed = true
		// try again without edns tags, some weird servers didn't implement that
		req = dnsutil.ClearOPT(req)
		return r.exchange(ctx, rs, interrupts, proto, req, server, retried)
	}

	return resp, nil
}

// dialerPool recycles net.Dialer structs across upstream queries. The
// struct is small (~176 bytes) but allocated on every single upstream
// query — with ~17 MB/60s of allocation observed at typical cold-cache
// load, reuse is worth the pool.
var dialerPool = sync.Pool{New: func() any { return new(net.Dialer) }}

// dialUDP opens a connected UDP socket to server.UDPAddr. It is the
// hot-path alternative to Dialer.DialContext: DialUDP takes pre-parsed
// *UDPAddr values and skips resolveAddrList / dialParallel / internal
// context wiring, none of which applies for numeric IP:port targets.
// DialUDP is non-blocking so no dial timeout is required; the caller
// still calls SetDeadline on the returned conn for read/write
// timeouts.
//
// The explicit error check below matters: a direct return of
// DialUDP's typed *net.UDPConn wraps a nil pointer in a non-nil
// net.Conn interface, and downstream code assumes `Conn != nil`
// means the conn is usable.
func (r *Resolver) dialUDP(server *authority.Server) (net.Conn, error) {
	laddr := r.localUDPAddrFor(server.IPVersion)
	conn, err := net.DialUDP("udp", laddr, server.UDPAddr)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// localUDPAddrFor returns the pre-built *net.UDPAddr to use as the
// local address on the outgoing socket, honouring the same round-robin
// selection newDialer does based on NumCPU rotation; nil means "let
// the kernel pick an ephemeral local endpoint".
func (r *Resolver) localUDPAddrFor(version authority.IPVersion) *net.UDPAddr {
	switch version {
	case authority.IPv4:
		if n := len(r.outboundUDPv4); n > 0 {
			return r.outboundUDPv4[localAddrIndex(n)]
		}
	case authority.IPv6:
		if n := len(r.outboundUDPv6); n > 0 {
			return r.outboundUDPv6[localAddrIndex(n)]
		}
	}
	return nil
}

// localAddrIndex rotates through the configured outbound IPs using a
// per-resolver atomic counter. The original newDialer path selects by
// request id; the UDP path can't easily read the id without a ctx, and
// a round-robin counter gives the same spread without the ctx lookup.
func localAddrIndex(n int) int {
	if n <= 1 {
		return 0
	}
	// The modulo result is in [0, n) and n is a small positive int,
	// so the uint64 -> int conversion is always safe.
	return int(localAddrCounter.Add(1) % uint64(n)) //nolint:gosec // G115 - modulo result is less than n
}

var localAddrCounter atomic.Uint64

// releaseDialer returns d to the pool after dialing is complete.
// Callers must not hold a reference to d after calling.
func releaseDialer(d *net.Dialer) {
	*d = net.Dialer{}
	dialerPool.Put(d)
}

func (r *Resolver) newDialer(ctx context.Context, rs *resolveState, proto string, version authority.IPVersion) (d *net.Dialer) {
	// Calculate deadline respecting both network timeout and context deadline
	deadline := time.Now().Add(r.netTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}

	d = dialerPool.Get().(*net.Dialer)
	d.Deadline = deadline

	// Outbound IP selection uses the outer client's request ID so all
	// upstream queries for one client query land on the same configured
	// IP. The id rides on resolveState; for sub-queries dispatched via
	// Queryer.Query the outer id is propagated through
	// contextKeyRequestID (set by DNSHandler.ServeDNS and preserved
	// across sub-pipeline re-entry) and re-read in Resolve when
	// building the child resolveState.
	reqid := int(rs.requestID)

	switch version {
	case authority.IPv4:
		if len(r.outboundIPv4) > 0 {
			// we will be select outbound ip address by request id.
			index := len(r.outboundIPv4) * reqid / maxUint16

			// port number will automatically chosen
			switch proto {
			case "tcp":
				d.LocalAddr = &net.TCPAddr{IP: r.outboundIPv4[index]}
			case "udp":
				d.LocalAddr = &net.UDPAddr{IP: r.outboundIPv4[index]}
			}
		}
	case authority.IPv6:
		if len(r.outboundIPv6) > 0 {
			index := len(r.outboundIPv6) * reqid / maxUint16

			// port number will automatically chosen
			switch proto {
			case "tcp":
				d.LocalAddr = &net.TCPAddr{IP: r.outboundIPv6[index]}
			case "udp":
				d.LocalAddr = &net.UDPAddr{IP: r.outboundIPv6[index]}
			}
		}
	}

	return d
}

// delegationMatch is the result of a delegation-cache walk: the servers to
// use, the DS set proving the delegation, the descent level, and the absolute
// expiry + identity of the matched cut (zero for the root, which is
// unbounded). The pair seeds resolveState so descendants inherit it.
type delegationMatch struct {
	servers  *authority.Servers
	parentDS []dns.RR
	level    int
	deadline time.Time
	key      uint64
}

func (r *Resolver) searchCache(q dns.Question, cd bool, origin string) delegationMatch {
	if q.Qtype == dns.TypeDS {
		// DS queries are answered by parent zone, move up one label
		next, end := dns.NextLabel(q.Name, 0)

		q.Name = q.Name[next:]
		if end {
			q.Name = rootzone
		}
	}

	q.Qtype = dns.TypeNS // we should search NS type in cache
	key := cache.Key(q, cd)

	ns, err := r.delegations.Get(key)

	if err == nil {
		if atomic.LoadUint32(&ns.Servers.ErrorCount) >= 10 {
			// we have fatal errors from all servers, lets clear cache and try again
			r.delegations.Remove(key)
			q.Name = origin
			return r.searchCache(q, cd, origin)
		}
		if debugLogEnabled() {
			zlog.Debug("Nameserver cache hit", "key", key, "query", dnsutil.FormatQuestion(q), "cd", cd)
		}
		return delegationMatch{
			servers:  ns.Servers,
			parentDS: ns.DSSet,
			level:    dnsname.CompareSuffix(origin, q.Name),
			deadline: ns.ExpiresAt,
			key:      key,
		}
	}

	// A CD=0 query must NEVER borrow a CD=1 delegation. Delegations are
	// keyed on the client's CD bit (see processDelegation), so a
	// proven-insecure CD=0 delegation already lives in this same CD=0
	// bucket and was returned above. The CD=1 bucket holds only
	// unvalidated results (CD=1 clients and internal NS/DS lookups);
	// serving one of those here would strip AD from a signed zone whose
	// DS lookup transiently returned empty.

	next, end := dns.NextLabel(q.Name, 0)

	if end {
		// Reached root zone: use root servers (unbounded — zero deadline).
		return delegationMatch{servers: r.rootServers, level: 0}
	}

	q.Name = q.Name[next:]

	return r.searchCache(q, cd, origin) // recursive walk up DNS tree
}

// findRRSIGSigners returns the distinct SignerName values from RRSIGs
// in the chosen section that cover an RRset actually present in that
// section. Returning all candidates (ordered by label count, most
// specific first) lets callers retry validation with each signer — RFC
// 6840 §5.11 says extra signatures from unknown keys must be
// disregarded, and an attacker may insert a garbage RRSIG with a
// plausible ancestor SignerName ahead of the legitimate one. Picking
// only the first signer would let that injected signature steer
// findDS() to the wrong zone and collapse a valid response into bogus.
func (r *Resolver) findRRSIGSigners(resp *dns.Msg, qname string, inAnswer bool) []string {
	rrset := resp.Ns
	if inAnswer {
		rrset = resp.Answer
	}

	type rrKey struct {
		name  string
		rtype uint16
	}
	have := make(map[rrKey]bool)
	for _, rr := range rrset {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			continue
		}
		have[rrKey{strings.ToLower(rr.Header().Name), rr.Header().Rrtype}] = true
	}

	seen := make(map[string]bool)
	var signers []string
	for _, rr := range rrset {
		sig, ok := rr.(*dns.RRSIG)
		if !ok {
			continue
		}
		// Drop RRSIGs that don't correspond to any record in the
		// section: a lone "garbage" RRSIG carries no useful signer.
		if !have[rrKey{strings.ToLower(sig.Header().Name), sig.TypeCovered}] {
			continue
		}
		dnameCover := sig.TypeCovered == dns.TypeDNAME
		if inAnswer && !strings.EqualFold(sig.Header().Name, qname) && !dnameCover {
			continue
		}
		key := strings.ToLower(dns.Fqdn(sig.SignerName))
		if seen[key] {
			continue
		}
		seen[key] = true
		signers = append(signers, sig.SignerName)
	}

	// Prefer the most specific (longest-labeled) signer first so the
	// legitimate zone apex is tried ahead of any shallower ancestor an
	// attacker might have injected. dnssec.ValidateSigner will reject any
	// candidate that isn't an ancestor of qname, so the candidate set
	// is naturally bounded by the number of ancestor zones of qname;
	// truncating the slice would only let an attacker pad with bogus
	// more-specific signers and push the real signer out of the retry
	// set, producing false SERVFAILs on deep qnames.
	sort.Slice(signers, func(i, j int) bool {
		iLabels, jLabels := dns.CountLabel(signers[i]), dns.CountLabel(signers[j])
		if iLabels != jLabels {
			return iLabels > jLabels
		}
		return strings.ToLower(dns.Fqdn(signers[i])) < strings.ToLower(dns.Fqdn(signers[j]))
	})
	return signers
}

func (r *Resolver) findDS(ctx context.Context, signer, qname string, parentDS []dns.RR, cd bool) (dsset []dns.RR, err error) {
	if signer == rootzone && len(parentDS) == 0 {
		parentDS, err = r.dsRRFromRootKeys(ctx)
		if err != nil {
			return nil, err
		}
	} else if len(parentDS) > 0 {
		dsrr := parentDS[0].(*dns.DS)
		dsname := strings.ToLower(dsrr.Header().Name)

		if signer == "" {
			// generally auth server directly return answer without DS records
			n := dnsname.CompareSuffix(dsname, qname)
			qnameLabels := dns.CountLabel(qname)

			for qnameLabels-n > 0 {
				// The candidate is qname's last n+1 labels — a suffix of a
				// name that is already rooted, so it is sliced rather than
				// split, joined and rooted again. The rooting guard costs a
				// byte check and keeps an unrooted caller, if one ever
				// appears, on the old behavior.
				prev, _ := dns.PrevLabel(qname, n+1)
				candidate := qname[prev:]
				if !dns.IsFqdn(candidate) {
					candidate = dns.Fqdn(candidate)
				}

				dsResp, err := r.lookupDS(ctx, candidate, cd)
				if err != nil {
					return nil, err
				}

				parentDS = dnsutil.ExtractRRSet(dsResp.Answer, candidate, dns.TypeDS)
				if len(parentDS) == 0 {
					break
				}

				n = dnsname.CompareSuffix(candidate, qname)
			}

		} else if dsname != signer {
			// try lookup DS records
			dsResp, err := r.lookupDS(ctx, signer, cd)
			if err != nil {
				return nil, err
			}

			parentDS = dnsutil.ExtractRRSet(dsResp.Answer, signer, dns.TypeDS)
		}
	}

	dsset = parentDS

	return
}

// isZoneSecure determines whether a missing RRSIG for qname should be treated
// as a DNSSEC failure. It returns true when the zone serving qname is known to
// be signed (i.e. has a DS record in the chain), meaning the absence of RRSIGs
// is a validation failure.
//
// Per RFC 4035 §5.2 and §5.3.3, if a DS record exists at a delegation point
// the child zone is expected to be signed and all answer RRsets MUST have
// RRSIGs. DS records only exist at zone cuts (RFC 4034 §5), so the presence
// of DS for a zone proves it is signed regardless of whether individual names
// inside the zone are delegation points themselves.
//
// When the zone parameter identifies the authoritative zone that produced the
// response, we check whether the DS in parentDS covers that zone directly.
// If not, we probe the zone's own delegation point (not internal names) to
// determine whether an insecure delegation exists between the ancestor and
// the zone.
func (r *Resolver) isZoneSecure(ctx context.Context, qname string, parentDS []dns.RR, zone string) bool {
	if !hasSupportedDS(parentDS) {
		// Either no DS records, or every DS uses a digest type this
		// validator cannot verify. RFC 6840 §5.2 treats such zones as
		// if DNSSEC were absent, so missing RRSIGs are acceptable.
		return false
	}

	dsrr := parentDS[0].(*dns.DS)
	dsname := strings.ToLower(dsrr.Header().Name)

	// If the DS record directly covers the zone that served the response,
	// the zone is signed and the missing RRSIG is a real failure
	// (RFC 4035 §5.3.3).
	if zone != "" && strings.EqualFold(dsname, zone) {
		return true
	}

	// The DS is from an ancestor zone. Probe the zone's own delegation
	// point to check whether it has a DS record. If zone is known, probe
	// it directly rather than walking into internal names that are not
	// zone cuts (RFC 4034 §5 — DS only exists at delegation points).
	probeName := zone
	if probeName == "" {
		// No zone info available; fall back to probing the parent of qname:
		// everything past the first label, sliced rather than split and
		// rejoined.
		probeName = qname
		if off, end := dns.NextLabel(qname, 0); !end {
			probeName = qname[off:]
			if !dns.IsFqdn(probeName) {
				probeName = dns.Fqdn(probeName)
			}
		}
	}

	// isZoneSecure is only reached from CD=0 validation paths, so
	// propagate cd=false into the internal DS walk here.
	parentDS, err := r.findDS(ctx, "", probeName, parentDS, false)
	if err != nil {
		// On lookup error, fail closed (assume signed) for safety.
		zlog.Debug("DS lookup failed during isZoneSecure, failing closed", "qname", qname, "error", err.Error())
		return true
	}

	return hasSupportedDS(parentDS)
}

// provenInsecureDelegation reports whether qname falls under a
// cryptographically proven insecure delegation lying strictly below
// `zone` — the deepest zone whose DS chain `parentDS` establishes.
//
// It exists for the case where one server is authoritative for both a
// signed parent and an unsigned child delegated from it, and answers a
// name in the child authoritatively — so the resolver crosses no referral
// and answer()/authority() never run validateDelegation's proof. Without
// this, the child's legitimately-unsigned records are misread as a signed
// zone missing its RRSIGs and bogused out (SERVFAIL).
//
// It walks each zone-cut candidate from just below `zone` toward qname.
// At a cut with a usable, validated DS it descends (secure). At the first
// cut with no DS it returns true ONLY when a signed NSEC/NSEC3 proves an
// insecure delegation (NS bit, no DS, no SOA) — exactly
// dnssec.VerifyDelegation. A name that merely lacks a DS without that
// delegation proof (an attacker stripping signatures off ordinary data in
// the signed parent) yields false and stays bogus, so this can never be
// used to downgrade. Any lookup/validation error also fails closed.
func (r *Resolver) provenInsecureDelegation(ctx context.Context, zone, qname string, parentDS []dns.RR) bool {
	zone = strings.ToLower(dns.Fqdn(zone))
	qname = strings.ToLower(dns.Fqdn(qname))
	if zone == "" || strings.EqualFold(qname, zone) || !dnsutil.NameInZone(qname, zone) {
		return false
	}

	qnameLabels := dns.CountLabel(qname)
	zoneCount := dns.CountLabel(zone)
	curDS := parentDS
	curSigner := zone

	// Candidates from just below `zone` (least specific) toward qname:
	// each is a suffix of qname, which is already canonical and rooted.
	for n := zoneCount + 1; n <= qnameLabels; n++ {
		prev, _ := dns.PrevLabel(qname, n)
		candidate := qname[prev:]

		dsset, insecure, err := r.authenticatedDelegationDS(ctx, curSigner, candidate, curDS)
		if err != nil {
			return false
		}
		if insecure {
			return true
		}
		if len(dsset) > 0 {
			// Secure delegation — descend and keep checking.
			curDS = dsset
			curSigner = candidate
			continue
		}
		return false
	}
	return false
}

// authenticatedDelegationDS returns the authenticated DS RRset for child, or
// insecure=true when the authenticated parent proof says child is an insecure
// delegation. The DS lookup itself runs with CD=1 because this helper performs
// the validation explicitly; using the normal CD=0 path here can re-enter the
// same missing-signature fallback and loop on the very proof being requested.
//
// NSEC3 opt-out coverage is accepted as the DS-denial proof, matching the
// referral path and other validators (RFC 5155 §6): in an opt-out zone an
// unsigned delegation has no exact-match NSEC3 by definition, so demanding
// one turns every legitimate name under the span into a false SERVFAIL
// (issue #506). This cannot be abused to downgrade signed data: a name that
// exists in the parent has an exact-match NSEC3 even in opt-out zones, and
// dnssec.VerifyDelegation tries the exact match first — signature stripping
// then fails on the missing NS bit. Forged names inside an opt-out span are
// accepted as insecure, which is the documented opt-out tradeoff every
// validator shares (RFC 5155 §12.2).
func (r *Resolver) authenticatedDelegationDS(ctx context.Context, signer, child string, parentDS []dns.RR) (dsset []dns.RR, insecure bool, err error) {
	dsResp, err := r.lookupDS(ctx, child, true)
	if err != nil {
		return nil, false, err
	}

	ok, verr := r.verifyDNSSEC(ctx, signer, child, dsResp, parentDS)
	if verr != nil {
		return nil, false, verr
	}
	if !ok {
		return nil, false, dnssec.ErrDSRecords
	}

	dsset = dnsutil.ExtractRRSet(dsResp.Answer, child, dns.TypeDS)
	if len(dsset) > 0 {
		if !hasSupportedDS(dsset) {
			return dsset, true, nil
		}
		return dsset, false, nil
	}

	if nsec3Set := dnsutil.FilterRRsToZone(dnsutil.ExtractRRSet(dsResp.Ns, "", dns.TypeNSEC3), signer); len(nsec3Set) > 0 {
		if err := dnssec.VerifyDelegationForZoneWithWork(
			child,
			signer,
			nsec3Set,
			r.dnssecWork(ctx),
		); err != nil {
			return nil, false, err
		}
		return nil, true, nil
	}
	if nsecSet := dnsutil.FilterRRsToZone(dnsutil.ExtractRRSet(dsResp.Ns, "", dns.TypeNSEC), signer); len(nsecSet) > 0 {
		if err := dnssec.VerifyDelegationNSEC(child, nsecSet); err != nil {
			return nil, false, err
		}
		return nil, true, nil
	}

	return nil, false, dnssec.ErrNSECMissingCoverage
}

// hasSupportedDS reports whether dsset contains at least one DS record
// that this validator can actually use — both its digest type and the
// DNSKEY algorithm it advertises must be supported. An unsupported-only
// DS set (GOST digest, ECCGOST algorithm, etc.) is treated as "no
// usable DS" per RFC 6840 §5.2, so missing RRSIGs for the child zone
// are tolerated as insecure data rather than flagged bogus.
func hasSupportedDS(dsset []dns.RR) bool {
	for _, rr := range dsset {
		if ds, ok := rr.(*dns.DS); ok && dnssec.IsSupportedDS(ds) {
			return true
		}
	}
	return false
}

func (r *Resolver) lookupDS(ctx context.Context, qname string, cd bool) (msg *dns.Msg, err error) {
	zlog.Debug("Lookup DS record", "qname", qname)

	dsReq := new(dns.Msg)
	dsReq.SetQuestion(qname, dns.TypeDS)
	dsReq.SetEdns0(dnsutil.DefaultMsgSize, true)
	// Inherit the outer client's CD bit so a CD=1 query doesn't have
	// its internal DS chain walk SERVFAIL on bogus parent-side DS data.
	dsReq.CheckingDisabled = cd

	dsres, err := r.subQuery(ctx, dsReq)
	if err != nil {
		return nil, err
	}

	if len(dsres.Answer) == 0 && len(dsres.Ns) == 0 {
		return nil, fmt.Errorf("DS or NSEC records not found")
	}

	return dsres, nil
}

// errQueryerNotWired is returned when an internal client-shaped
// lookup fires before sdns.go wiring has installed a Queryer.
// Production never sees this path; it exists so tests that build a
// partially wired Resolver get a clear error instead of a nil deref.
var errQueryerNotWired = errors.New("resolver: queryer not wired")

// internalExchange routes a resolver-constructed client-shaped
// lookup (NS A/AAAA, DNAME target) through the installed Queryer.
//
// This is distinct from subQuery: the latter bypasses the chain
// entirely for DNSSEC records where policy overrides would
// compromise the chain of trust. internalExchange goes through the
// sub-pipeline so hostsfile, blocklist, kubernetes, as112, and
// failover all still apply.
func (r *Resolver) internalExchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	q := r.queryer.Load()
	if q == nil {
		return nil, errQueryerNotWired
	}
	return (*q).Query(ctx, req)
}

// subQuery answers a resolver-constructed DNSSEC record lookup (DS
// or DNSKEY) via cache-first direct resolution. It deliberately
// bypasses the middleware chain — no failover, no local-answer
// middleware (hostsfile, blocklist, kubernetes, as112) — because
// the DNSSEC chain of trust must not be polluted by operator
// overrides or configured forwarders substituting for authoritative
// signer-zone records.
//
// NS A/AAAA, DNAME target, and CNAME chase go through queryer.Queryer
// instead; those resolutions are legitimately subject to operator
// policy and do not participate in signature validation.
//
// requestID is read from ctx (contextKeyRequestID, populated by the
// outer DNSHandler.ServeDNS) so newDialer inherits the outer
// client's outbound-IP spread for sub-query traffic. Threading rs
// through every DNSSEC helper would require touching findDS /
// answer / authority / isZoneSecure / validateDelegation signatures;
// ctx is already plumbed everywhere and carries the same value that
// Resolve() would read when building a state struct.
//
// subQuery is nil-safe for a nil store — tests and forwarder-only
// deployments construct a Resolver without one. In that case only
// the direct-upstream path runs; nothing is cached or read.
func (r *Resolver) subQuery(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	store := r.store.Load()
	if store != nil {
		var (
			msg *dns.Msg
			ok  bool
		)
		if contextStore, aware := (*store).(middleware.ContextStore); aware {
			msg, ok = contextStore.GetWithContext(ctx, req)
		} else {
			msg, ok = (*store).Get(req)
		}
		if ok {
			return msg, nil
		}
	}
	if err := middleware.DebitRecursionWork(ctx, middleware.RecursionWorkInternalQuery); err != nil {
		return nil, err
	}

	// Clear RD/AD before hitting authoritative servers.
	// DNSHandler.handle does this at handler.go:134-135 for chain-
	// dispatched queries; subQuery bypasses the handler entirely,
	// so resolver-constructed DS/DNSKEY requests (all built via
	// dns.Msg.SetQuestion, which defaults RD=true) would otherwise
	// ask authorities for recursion and trip REFUSED on stricter
	// ones. req is always constructed by the immediate caller
	// (lookupDS, verifyDNSSEC) and not shared, so a plain mutate
	// is safe; no save/restore needed.
	req.RecursionDesired = false
	req.AuthenticatedData = false

	reqid := req.Id
	if v := requestIDFromContext(ctx); v != nil {
		if id, ok := v.(uint16); ok {
			reqid = id
		}
	}

	// Depth budget mirrors handler.go's Maxdepth handling: the cfg
	// default set in New() is 30, but some tests construct a Resolver
	// directly with cfg == nil and rely on internal lookups failing
	// closed rather than panicking.
	depth := 30
	if r.cfg != nil && r.cfg.Maxdepth > 0 {
		depth = r.cfg.Maxdepth
	}

	// Fail closed when root servers aren't configured. Production
	// startup always populates root servers; tests that construct
	// Resolver{} directly rely on this fail-closed path rather than
	// a panic deep in resolve().
	if r.rootServers == nil {
		return nil, errNoRootServers
	}

	child := &resolveState{
		req:     req,
		servers: r.rootServers,
		depth:   depth,
		level:   0,
		// Minimization hides the client's name. What reaches here is the
		// resolver's own bookkeeping — a DS or DNSKEY at a delegation point
		// the parent already serves — so there is nothing left to hide, and
		// minimizing it let every internal lookup start a walk of its own.
		nomin:     true,
		parentDS:  nil,
		isRoot:    true,
		extra:     nil,
		requestID: reqid,
		work:      middleware.RecursionWorkFrom(ctx),
	}
	resp, err := r.resolve(ctx, child)
	if child.work != nil {
		if workErr := child.work.EnforcementError(); workErr != nil {
			return nil, workErr
		}
	}
	if err != nil {
		return nil, err
	}
	if store != nil && resp != nil {
		// Bound the entry to the delegation cut the sub-resolution
		// walked (its terminal noteCut calls fed the same ctx sink).
		// Zero when no sink exists (priming/background) — unbounded,
		// matching the pre-seam behaviour.
		var (
			cutUntil time.Time
			cutKey   uint64
		)
		if meta := middleware.ResponseMetaFrom(ctx); meta != nil {
			cutUntil, cutKey = meta.Cut()
		}
		if cutStore, ok := (*store).(middleware.CutStore); ok {
			cutStore.SetFromResponseWithCut(resp, req.CheckingDisabled, cutUntil, cutKey)
		} else {
			(*store).SetFromResponse(resp, req.CheckingDisabled, cutUntil)
		}
	}
	return resp, nil
}

func (r *Resolver) lookupNSAddrV4(ctx context.Context, qname string, cd bool) (addrs []netip.Addr, err error) {
	zlog.Debug("Lookup NS ipv4 address", "qname", qname)

	if addrs, ok := r.getIPv4Cache(qname); ok {
		return addrs, nil
	}

	ctx = context.WithValue(ctx, contextKeyNSL, struct{}{})

	nsReq := new(dns.Msg)
	nsReq.SetQuestion(qname, dns.TypeA)
	nsReq.SetEdns0(dnsutil.DefaultMsgSize, true)
	nsReq.CheckingDisabled = cd

	nsres, err := r.internalExchange(ctx, nsReq)
	if err != nil {
		return addrs, fmt.Errorf("nameserver ipv4 address lookup failed for %s: %w", qname, err)
	}

	if addrs, ok := searchAddrs(nsres); ok {
		return addrs, nil
	}

	// try look glue cache
	if addrs, ok := r.getIPv4Cache(qname); ok {
		return addrs, nil
	}

	return addrs, fmt.Errorf("nameserver ipv4 address lookup failed for %s", qname)
}

func (r *Resolver) lookupNSAddrV6(ctx context.Context, qname string, cd bool) (addrs []netip.Addr, err error) {
	zlog.Debug("Lookup NS ipv6 address", "qname", qname)

	if addrs, ok := r.getIPv6Cache(qname); ok {
		return addrs, nil
	}

	ctx = context.WithValue(ctx, contextKeyNSL, struct{}{})

	nsReq := new(dns.Msg)
	nsReq.SetQuestion(qname, dns.TypeAAAA)
	nsReq.SetEdns0(dnsutil.DefaultMsgSize, true)
	nsReq.CheckingDisabled = cd

	nsres, err := r.internalExchange(ctx, nsReq)
	if err != nil {
		return addrs, fmt.Errorf("nameserver ipv6 address lookup failed for %s: %w", qname, err)
	}

	if addrs, ok := searchAddrs(nsres); ok {
		return addrs, nil
	}

	// try look glue cache
	if addrs, ok := r.getIPv6Cache(qname); ok {
		return addrs, nil
	}

	return addrs, fmt.Errorf("nameserver ipv6 address lookup failed for %s", qname)
}

func (r *Resolver) lookupV4Nss(ctx context.Context, q dns.Question, authservers *authority.Servers, key uint64, parentDS []dns.RR, foundv4, hosts hostSet, cd bool, cutDeadline time.Time) error {
	list := sortHosts(hosts, q.Name)
	var lastAttemptLimit error

	for _, name := range list {
		// Hosts is copied by readers (checkHosts) under RLock once
		// the Servers pointer is published via delegations.Set
		// below, so this append must take the same Lock —
		// otherwise cold delegation bursts race on the slice
		// header/backing array.
		authservers.Lock()
		authservers.Hosts = append(authservers.Hosts, name)
		authservers.Unlock()

		if _, ok := foundv4[name]; ok {
			continue
		}

		ctx, loop := r.checkLoop(ctx, name, dns.TypeA)
		if loop {
			if _, ok := r.getIPv4Cache(name); !ok {
				zlog.Debug("Looping during ns ipv4 lookup", "query", dnsutil.FormatQuestion(q), "ns", name)
				continue
			}
		}

		authservers.RLock()
		hasList := len(authservers.List) > 0
		authservers.RUnlock()
		if hasList && (!r.dnssec || r.hasTrustAnchors()) {
			// Temporary cache before lookup. Skip when trust anchors
			// are unavailable: the DS set could be empty because the
			// DNSSEC chain was short-circuited, and caching that empty-DS
			// entry would make a signed zone look insecure after recovery.
			//
			// Bound this provisional entry by the (inherited) cut deadline,
			// stored as an absolute expiry — a flat one-minute route, or a
			// lease restarted across several NS lookups, would outlive a
			// 1-4s parent referral and keep a withdrawn child reachable
			// (GHSA-mqfw-f48p-2vc8). Cap it at one minute so a long-lived cut
			// still refreshes the provisional set promptly. A past deadline
			// is not cached (SetUntil skips it).
			r.delegations.SetUntil(key, parentDS, authservers, minNonZero(cutDeadline, time.Now().Add(time.Minute)))
		}

		addrs, err := r.lookupNSAddrV4(ctx, name, cd)
		nsipv4 := make(map[string][]netip.Addr)

		if err != nil {
			if errors.Is(err, middleware.ErrRecursionWorkLimit) ||
				errors.Is(err, middleware.ErrMaxRecursion) ||
				errors.Is(err, context.Canceled) ||
				errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			if errors.Is(err, middleware.ErrResolutionAttemptLimit) {
				// RFC 9520 keys by question tuple: exhausting one NS
				// hostname must not prevent trying the delegation's other
				// hostnames.
				lastAttemptLimit = err
				zlog.Debug("Lookup NS ipv4 address reached attempt limit", "query", dnsutil.FormatQuestion(q), "ns", name)
				continue
			}
			zlog.Debug("Lookup NS ipv4 address failed", "query", dnsutil.FormatQuestion(q), "ns", name, "error", err.Error())
			continue
		}

		if len(addrs) == 0 {
			continue
		}

		nsipv4[name] = addrs

		authservers.Lock()
		before := len(authservers.List)
	addrsloop:
		for _, addr := range addrs {
			endpoint := netip.AddrPortFrom(addr, 53)
			for _, s := range authservers.List {
				if s.UDPAddr != nil && s.UDPAddr.AddrPort() == endpoint {
					continue addrsloop
				}
			}
			authservers.List = append(authservers.List, authority.NewServerFromAddrPort(endpoint))
		}
		if len(authservers.List) != before {
			// Invalidate *before* releasing the write lock: after
			// Unlock() a reader could observe the mutated List with
			// fpValid still true and get a stale cached hash.
			authservers.InvalidateFingerprint()
		}
		authservers.Unlock()
		r.addIPv4Cache(nsipv4)
	}

	if lastAttemptLimit != nil {
		authservers.RLock()
		hasServer := len(authservers.List) > 0
		authservers.RUnlock()
		if !hasServer {
			return lastAttemptLimit
		}
	}
	return nil
}

func (r *Resolver) lookupV6Nss(ctx context.Context, q dns.Question, authservers *authority.Servers, foundv6, hosts hostSet, cd bool) {
	// IPv6 glue discovery enriches an already usable delegation. It must stop
	// at the originating request tree's shared cap, but its rejected debit
	// must not poison the required resolution path.
	ctx = middleware.WithBestEffortRecursionWork(ctx)

	// Let the main (IPv4) path drain its auth-server rate-limit budget
	// before we pile on IPv6 probes, but don't spend the full delay
	// sleeping when ctx (e.g. the 30s v6-lookup budget upstream) has
	// already fired. time.NewTimer + defer Stop releases the timer if
	// ctx wins; time.After would leave it pending until defaultTimeout
	// elapses.
	t := time.NewTimer(defaultTimeout)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
		return
	}

	list := sortHosts(hosts, q.Name)

	for _, name := range list {
		if _, ok := foundv6[name]; ok {
			continue
		}

		ctx, loop := r.checkLoop(ctx, name, dns.TypeAAAA)
		if loop {
			if _, ok := r.getIPv6Cache(name); !ok {
				zlog.Debug("Looping during ns ipv6 lookup", "query", dnsutil.FormatQuestion(q), "ns", name)
				continue
			}
		}

		addrs, err := r.lookupNSAddrV6(ctx, name, cd)
		nsipv6 := make(map[string][]netip.Addr)

		if err != nil {
			if errors.Is(err, middleware.ErrRecursionWorkLimit) ||
				errors.Is(err, middleware.ErrMaxRecursion) {
				return
			}
			// Keep going: one nameserver without an AAAA (or rate
			// limited) must not prevent subsequent NSs in the
			// delegation from contributing IPv6 addresses. The IPv4
			// path in lookupV4Nss uses the same continue semantic.
			zlog.Debug("Lookup NS ipv6 address failed", "query", dnsutil.FormatQuestion(q), "ns", name, "error", err.Error())
			continue
		}

		if len(addrs) == 0 {
			continue
		}

		nsipv6[name] = addrs

		authservers.Lock()
		before := len(authservers.List)
	addrsloop:
		for _, addr := range addrs {
			endpoint := netip.AddrPortFrom(addr, 53)
			for _, s := range authservers.List {
				if s.UDPAddr != nil && s.UDPAddr.AddrPort() == endpoint {
					continue addrsloop
				}
			}
			authservers.List = append(authservers.List, authority.NewServerFromAddrPort(endpoint))
		}
		if len(authservers.List) != before {
			authservers.InvalidateFingerprint()
		}
		authservers.Unlock()
		r.addIPv6Cache(nsipv6)
	}
}

// hasTrustAnchors reports whether at least one root trust anchor is
// currently usable for DNSSEC validation. AutoTA clears r.rootKeys
// when it can't prove revocation permanence (corrupt tombstone store,
// etc.); validation paths call this to fail closed instead of
// slipping into the "unsigned delegation" branch with no anchor.
func (r *Resolver) hasTrustAnchors() bool {
	r.RLock()
	defer r.RUnlock()
	return len(r.rootKeys) > 0
}

func (r *Resolver) dsRRFromRootKeys(ctx context.Context) ([]dns.RR, error) {
	r.RLock()
	rootKeys := append([]dns.RR(nil), r.rootKeys...)
	r.RUnlock()

	dsset := make([]dns.RR, 0, len(rootKeys))
	work := r.dnssecWork(ctx)
	for _, rr := range rootKeys {
		if dnskey, ok := rr.(*dns.DNSKEY); ok {
			ds, err := dnssec.DNSKEYToDSWithWork(dnskey, dns.DH, work)
			if err != nil {
				return nil, err
			}
			if ds != nil {
				dsset = append(dsset, ds)
			}
		}
	}

	if len(dsset) == 0 {
		return nil, dnssec.ErrTrustAnchorsUnavailable
	}

	return dsset, nil
}

func (r *Resolver) verifyRootKeys(ctx context.Context, msg *dns.Msg) (bool, error) {
	r.RLock()
	rootKeys := append([]dns.RR(nil), r.rootKeys...)
	r.RUnlock()

	keys := make(map[uint16][]*dns.DNSKEY)
	for _, rr := range rootKeys {
		dnskey := rr.(*dns.DNSKEY)
		if dnskey.Flags == 257 {
			tag := dnssec.KeyTag(dnskey)
			keys[tag] = append(keys[tag], dnskey)
		}
	}

	if len(keys) == 0 {
		return false, dnssec.ErrTrustAnchorsUnavailable
	}

	dsset, err := r.dsRRFromRootKeys(ctx)
	if err != nil {
		return false, err
	}

	work := r.dnssecWork(ctx)
	if _, err := dnssec.VerifyDSWithWork(keys, dsset, work); err != nil {
		return false, err
	}

	if _, err := dnssec.VerifyRRSIGWithWork(rootzone, keys, msg, work); err != nil {
		return false, err
	}

	return true, nil
}

func (r *Resolver) verifyDNSSEC(ctx context.Context, signer, signed string, resp *dns.Msg, parentdsRR []dns.RR) (ok bool, err error) {
	keyReq := new(dns.Msg)
	keyReq.SetQuestion(signer, dns.TypeDNSKEY)
	keyReq.SetEdns0(dnsutil.DefaultMsgSize, true)

	var msg *dns.Msg

	q := resp.Question[0]

	if q.Qtype != dns.TypeDNSKEY || q.Name != signer {
		msg, err = r.subQuery(ctx, keyReq)
		if err != nil {
			return
		}
	} else if q.Qtype == dns.TypeDNSKEY {
		if q.Name == rootzone {
			ok, rootErr := r.verifyRootKeys(ctx, resp)
			if rootErr != nil {
				return false, rootErr
			}
			if !ok {
				return false, fmt.Errorf("root zone keys not verified")
			}
			return true, nil
		}

		msg = resp
	}

	// RFC 4034 Appendix B.1: key tags are *not* unique. A colliding tag
	// would silently overwrite a matching key in a single-valued map
	// and turn a valid DS/RRSIG chain into a bogus result. Keep every
	// DNSKEY whose tag matches and let verify paths try them all.
	//
	// Only keep DNSKEYs whose owner matches the signer zone: an
	// attacker can append a same-tag clone with a different owner to
	// the DNSKEY response and, if it sorted first in map iteration,
	// the old signer-zone derivation treated its owner as the signer
	// zone and rejected legitimate in-zone RRsets as foreign.
	keys := make(map[uint16][]*dns.DNSKEY)
	signerLower := strings.ToLower(dns.Fqdn(signer))
	for _, a := range msg.Answer {
		if a.Header().Rrtype == dns.TypeDNSKEY {
			dnskey := a.(*dns.DNSKEY)
			if !strings.EqualFold(dnskey.Header().Name, signerLower) {
				continue
			}
			if dnskey.Flags == 256 || dnskey.Flags == 257 {
				tag := dnssec.KeyTag(dnskey)
				keys[tag] = append(keys[tag], dnskey)
			}
		}
	}

	if len(keys) == 0 {
		return false, dnssec.ErrNoDNSKEY
	}

	if len(parentdsRR) == 0 {
		return false, fmt.Errorf("DS RR set empty")
	}

	unsupportedOnly, err := dnssec.VerifyDSWithWork(keys, parentdsRR, r.dnssecWork(ctx))
	if err != nil {
		zlog.Debug("DNSSEC DS verify failed", "signer", signer, "signed", signed, "error", err.Error(), "unsupported only", unsupportedOnly)
		if unsupportedOnly {
			// Every DS digest was unsupported — RFC 6840 §5.2
			// requires treating the zone as if DNSSEC were absent
			// (insecure), not bogus.
			return false, nil
		}
		return
	}

	// we don't need to verify rrsig questions.
	if q.Qtype == dns.TypeRRSIG {
		return false, nil
	}

	if ok, err = dnssec.VerifyRRSIGWithWork(signer, keys, resp, r.dnssecWork(ctx)); err != nil {
		return
	}

	// Cannot verify DNSSEC keys with RSA exponents > 2^31-1 due to Go crypto/rsa limitation
	// See https://github.com/golang/go/issues/3161
	if !ok {
		return false, nil
	}

	if debugLogEnabled() {
		zlog.Debug("DNSSEC verified", "signer", signer, "signed", signed, "query", dnsutil.FormatQuestion(resp.Question[0]))
	}

	return true, nil
}

func (r *Resolver) clearAdditional(req, resp *dns.Msg, extra ...bool) *dns.Msg {
	// Always clear authority section
	resp.Ns = []dns.RR{}

	// Clear extra section unless told to keep it (default is to clear)
	shouldClearExtra := len(extra) == 0 || !extra[0]

	if shouldClearExtra {
		resp.Extra = []dns.RR{}

		// Preserve EDNS0 if present
		if opt := req.IsEdns0(); opt != nil {
			resp.Extra = append(resp.Extra, opt)
		}
	}

	return resp
}

func (r *Resolver) equalServers(s1, s2 *authority.Servers) bool {
	// Cheap probable-equality check: identical cached fingerprints
	// imply identical sorted address sets. False positives are
	// statistically negligible for 64-bit FNV over a handful of
	// addresses, and equalServers is only used for loop detection,
	// not a correctness invariant.
	return s1.Fingerprint() == s2.Fingerprint()
}

func (r *Resolver) checkPriming() {
	req := new(dns.Msg)
	req.SetQuestion(rootzone, dns.TypeNS)
	req.SetEdns0(dnsutil.DefaultMsgSize, true)
	req.CheckingDisabled = !r.dnssec

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(r.netTimeout))
	defer cancel()

	if len(r.rootServers.List) == 0 {
		zlog.Fatal("Root servers list empty. check your config file")
	}

	resp, err := r.Resolve(ctx, req, r.rootServers, true, 5, 0, false, nil, true)
	if err != nil {
		zlog.Error("Root servers update failed", "error", err.Error())
		return
	}

	if r.dnssec && !resp.AuthenticatedData {
		zlog.Error("Root servers update failed", "error", "not authenticated")
		return
	}

	// Count NS records and build a map of root server names
	nsServers := make(map[string]bool)
	for _, r := range resp.Answer {
		if ns, ok := r.(*dns.NS); ok {
			nsServers[strings.ToLower(ns.Ns)] = true
		}
	}

	if len(nsServers) == 0 {
		zlog.Error("Root servers update failed", "error", "no NS records in response")
		return
	}

	zlog.Debug("Root priming response", "ns_count", len(nsServers), "answer", len(resp.Answer), "extra", len(resp.Extra))

	var tmpservers authority.Servers
	foundServers := make(map[string]bool)
	seenEndpoints := make(map[netip.AddrPort]struct{})

	// Process IPv6 addresses if enabled
	if r.cfg.IPv6Access { //nolint:gosec // G118 - detached enrichment is intentionally bounded below
		for _, r := range resp.Extra {
			if v6, ok := r.(*dns.AAAA); ok {
				serverName := strings.ToLower(v6.Header().Name)
				if nsServers[serverName] {
					foundServers[serverName] = true
					if addr, valid := netip.AddrFromSlice(v6.AAAA); valid {
						endpoint := netip.AddrPortFrom(addr.Unmap(), 53)
						if _, ok := seenEndpoints[endpoint]; !ok {
							seenEndpoints[endpoint] = struct{}{}
							tmpservers.List = append(tmpservers.List, authority.NewServerFromAddrPort(endpoint))
						}
					}
				}
			}
		}
	}

	// Process IPv4 addresses
	for _, r := range resp.Extra {
		if v4, ok := r.(*dns.A); ok {
			serverName := strings.ToLower(v4.Header().Name)
			if nsServers[serverName] {
				foundServers[serverName] = true
				if addr, valid := netip.AddrFromSlice(v4.A); valid {
					endpoint := netip.AddrPortFrom(addr.Unmap(), 53)
					if _, ok := seenEndpoints[endpoint]; !ok {
						seenEndpoints[endpoint] = struct{}{}
						tmpservers.List = append(tmpservers.List, authority.NewServerFromAddrPort(endpoint))
					}
				}
			}
		}
	}

	// Verify we got addresses for at least some nameservers
	if len(foundServers) == 0 {
		zlog.Error("Root servers update failed", "error", "no A/AAAA records found for NS records")
		return
	}

	// Log a warning if we didn't get addresses for all nameservers (but continue)
	if len(foundServers) < len(nsServers) {
		zlog.Debug("Some root servers missing addresses", "ns_count", len(nsServers), "found", len(foundServers))
	}

	if len(tmpservers.List) >= len(r.rootServers.List) {
		r.rootServers.Lock()
		r.rootServers.List = tmpservers.List
		r.rootServers.Checked = true
		r.rootServers.InvalidateFingerprint()
		r.rootServers.Unlock()
		return
	}

	zlog.Error("Root servers update failed", "error", "missing A/AAAA records")
}

func (r *Resolver) run() {
	for !middleware.Ready() {
		// wait middleware setup
		time.Sleep(50 * time.Millisecond)
	}

	r.checkPriming() // update root server list from priming query
	if r.dnssec {
		r.AutoTA() // RFC 5011 automated trust anchor updates
	}

	ticker := time.NewTicker(12 * time.Hour)

	for range ticker.C {
		r.checkPriming()
		if r.dnssec {
			r.AutoTA()
		}
	}
}

// handleLookupError processes errors from groupLookup.
func (r *Resolver) handleLookupError(ctx context.Context, err error, rs *resolveState, minReq *dns.Msg, minimized bool) (*dns.Msg, error) {
	if errors.Is(err, middleware.ErrRecursionWorkLimit) ||
		errors.Is(err, middleware.ErrMaxRecursion) {
		return nil, err
	}

	if minimized {
		// retry without minimization
		rs.nomin = true
		rs.isRoot = false
		return r.resolve(ctx, rs)
	}
	if errors.Is(err, middleware.ErrResolutionAttemptLimit) {
		return nil, err
	}

	if isFatalError(err) {
		// no check for nsaddrs lookups
		if v := ctx.Value(contextKeyNSL); v != nil {
			return nil, err
		}

		zlog.Debug("Received network error from all servers", "query", dnsutil.FormatQuestion(minReq.Question[0]))

		if atomic.AddUint32(&rs.servers.ErrorCount, 1) == 5 {
			if ok := r.checkHosts(ctx, rs.servers); ok {
				return r.resolve(ctx, rs)
			}
		}
		r.recordResolutionZoneFailure(ctx, rs.req.Question[0], rs.servers.Zone, err)
	}
	return nil, err
}

// recordResolutionZoneFailure publishes only terminal, required-path
// authority failures. Request-local policy limits, cancellation, and detached
// best-effort enrichment must not create shared RFC 9520 failure state.
func (r *Resolver) recordResolutionZoneFailure(ctx context.Context, q dns.Question, zone string, cause error) {
	if zone == "" ||
		middleware.IsBestEffortRecursionWork(ctx) ||
		contextutil.EffectiveError(ctx) != nil ||
		errors.Is(cause, context.Canceled) ||
		errors.Is(cause, context.DeadlineExceeded) ||
		errors.Is(cause, middleware.ErrRecursionWorkLimit) ||
		errors.Is(cause, middleware.ErrResolutionAttemptLimit) ||
		errors.Is(cause, middleware.ErrMaxRecursion) {
		return
	}

	store := r.store.Load()
	if store == nil {
		return
	}
	if failures, ok := (*store).(middleware.ResolutionFailureStore); ok {
		failures.RecordZoneFailure(q, zone)
	}
}

func (r *Resolver) clearResolutionZoneFailure(q dns.Question, zone string) {
	if zone == "" {
		return
	}
	store := r.store.Load()
	if store == nil {
		return
	}
	if failures, ok := (*store).(middleware.ResolutionFailureStore); ok {
		failures.ClearZoneFailure(q, zone)
	}
}

// processAuthoritySection handles the authority section of the response.
func (r *Resolver) processAuthoritySection(ctx context.Context, rs *resolveState, minReq *dns.Msg, resp *dns.Msg, minimized bool) (*dns.Msg, error) {
	if minimized {
		// RFC 8020: a locally authenticated NXDOMAIN at a minimized name
		// denies that exact subtree, so there is no reason to continue
		// querying progressively longer names. Validate the real
		// authoritative query cycle first. Unsigned and checking-disabled
		// answers keep the historical deeper walk; bogus signed proofs fail
		// closed through authority().
		if resp.Rcode == dns.RcodeNameError {
			hasSOA := false
			for _, rr := range resp.Ns {
				if _, ok := rr.(*dns.SOA); ok {
					hasSOA = true
					break
				}
			}
			if hasSOA {
				result, err := r.authority(ctx, minReq, resp, rs.parentDS, rs.servers.Zone)
				if err != nil {
					return nil, err
				}
				negative, secure := middleware.ValidatedNegativeProofForResponse(ctx, result)
				if secure && negative.Aggressive &&
					negative.Proof != nil &&
					negative.Proof.Rcode == dns.RcodeNameError &&
					!dnsutil.HasNSEC3OptOut(result.Ns, negative.Zone) {
					// Provenance keeps minReq's denied name. Only the
					// client-visible Question is rebound to the original
					// full QNAME.
					result.Question = append([]dns.Question(nil), rs.req.Question...)
					r.clearResolutionZoneFailure(rs.req.Question[0], rs.servers.Zone)
					return result, nil
				}
			}
		}

		// Check if we need to continue with minimization
		for _, rr := range resp.Ns {
			switch rr.(type) {
			case *dns.SOA, *dns.CNAME:
				rs.advance(minimized)
				rs.isRoot = false
				return r.resolve(ctx, rs)
			}
		}
	}

	// Extract nameserver information
	nsInfo := r.extractDelegationInfo(resp)
	if len(nsInfo.hosts) == 0 {
		result, err := r.authority(ctx, minReq, resp, rs.parentDS, rs.servers.Zone)
		if err == nil {
			r.clearResolutionZoneFailure(rs.req.Question[0], rs.servers.Zone)
		}
		return result, err
	}

	// Handle SOA records
	if nsInfo.hasSOA {
		resp.Ns = r.filterAuthorityRecords(resp.Ns)
		result, err := r.authority(ctx, minReq, resp, rs.parentDS, rs.servers.Zone)
		if err == nil {
			r.clearResolutionZoneFailure(rs.req.Question[0], rs.servers.Zone)
		}
		return result, err
	}

	// Process delegation
	return r.processDelegation(ctx, rs, resp, nsInfo, minimized)
}

// delegationInfo holds extracted nameserver information.
type delegationInfo struct {
	hosts      hostSet
	nsRecord   *dns.NS
	nsTTL      uint32
	hasSOA     bool
	incoherent bool
}

// extractDelegationInfo extracts nameserver information from response.
func (r *Resolver) extractDelegationInfo(resp *dns.Msg) delegationInfo {
	info := delegationInfo{
		hosts: make(hostSet),
	}

	for _, rr := range resp.Ns {
		switch v := rr.(type) {
		case *dns.SOA:
			info.hasSOA = true
		case *dns.NS:
			h := v.Header()
			if info.nsRecord == nil {
				// First NS anchors the referral RRset (owner + class).
				info.nsRecord = v
				info.nsTTL = h.Ttl
				info.hosts[strings.ToLower(v.Ns)] = struct{}{}
				continue
			}
			// A single delegation is one coherent NS RRset: same owner,
			// same class. Ignore records from a different owner/class
			// rather than blending their targets and TTLs into one
			// delegation — a mixed-owner Authority section is not a valid
			// referral and must not widen the cached nameserver set.
			if !strings.EqualFold(h.Name, info.nsRecord.Header().Name) || h.Class != info.nsRecord.Header().Class {
				info.incoherent = true
				continue
			}
			// Lease for the MINIMUM TTL across the RRset, not the last
			// record's TTL.
			if h.Ttl < info.nsTTL {
				info.nsTTL = h.Ttl
			}
			info.hosts[strings.ToLower(v.Ns)] = struct{}{}
		}
	}

	return info
}

// minRRSetTTL returns the smallest TTL among rrs, or 0 when rrs is empty.
func minRRSetTTL(rrs []dns.RR) uint32 {
	var m uint32
	for i, rr := range rrs {
		if t := rr.Header().Ttl; i == 0 || t < m {
			m = t
		}
	}
	return m
}

// progressingReferral reports whether a referral delegating `referral`,
// received while querying the servers for `authZone` in service of `qname`,
// legitimately moves resolution forward. It must be a STRICT descendant of
// the zone we asked (in bailiwick) and an ancestor of the name we are
// resolving. An equal/shallower self-referral or an unrelated deeper name is
// rejected, so a former child cannot reinsert its own delegation and an
// off-path server cannot inject one (GHSA-mqfw-f48p-2vc8).
func progressingReferral(referral, authZone, qname string) bool {
	if !dnsname.Sub(authZone, referral) {
		return false // out of bailiwick
	}
	if strings.EqualFold(dns.CanonicalName(referral), dns.CanonicalName(authZone)) {
		return false // same zone — not strictly below the authority
	}
	return dnsname.Sub(referral, qname) // must be on the path to qname
}

// validReferral applies one coherent rule at both lookup winner selection and
// the processDelegation cache boundary. Rejecting a bad fast responder here
// leaves slower healthy authorities eligible to answer the same lookup.
func validReferral(info delegationInfo, authZone string, q dns.Question) bool {
	return info.nsRecord != nil &&
		!info.incoherent &&
		info.nsRecord.Header().Class == q.Qclass &&
		progressingReferral(info.nsRecord.Header().Name, authZone, q.Name)
}

// filterAuthorityRecords filters authority records for SOA responses.
func (r *Resolver) filterAuthorityRecords(nsRecords []dns.RR) []dns.RR {
	filtered := []dns.RR{}
	for _, rr := range nsRecords {
		switch rr.(type) {
		case *dns.SOA, *dns.NSEC, *dns.NSEC3, *dns.RRSIG:
			filtered = append(filtered, rr)
		}
	}
	return filtered
}

// processDelegation handles delegation processing.
func (r *Resolver) processDelegation(ctx context.Context, rs *resolveState, resp *dns.Msg, nsInfo delegationInfo, minimized bool) (*dns.Msg, error) {
	nsrr := nsInfo.nsRecord
	q := dns.Question{Name: nsrr.Header().Name, Qtype: nsrr.Header().Rrtype, Qclass: nsrr.Header().Class}
	// Delegation identity is keyed on the client's CD bit, matching
	// searchCache. It travels with the winning cut deadline into answer-cache
	// metadata so a future Phase-3 generation check can identify the owner.
	keyCD := rs.req.CheckingDisabled
	key := cache.Key(q, keyCD)

	// Ghost-domain guard (GHSA-mqfw-f48p-2vc8): a referral MUST progress
	// strictly below the zone we queried. A former child that returns its
	// own same-depth (or shallower) delegation — e.g. after the parent has
	// withdrawn it — would otherwise reinsert that delegation and resurrect
	// the domain. The main lookup loop routes such non-progressing referrals
	// to configErrors, but pickFallbackResponse can still surface one, so
	// reject it here before it can reach the delegation cache. The referral
	// must be a strict descendant of the queried zone AND an ancestor of the
	// name we are resolving.
	if !validReferral(nsInfo, rs.servers.Zone, rs.req.Question[0]) {
		zlog.Debug("Rejecting non-progressing delegation", "zone", rs.servers.Zone, "referral", q.Name, "qname", rs.req.Question[0].Name)
		return nil, errParentDetection
	}

	// Capture ONE observation instant BEFORE validation and derive both the
	// NS and DS deadlines from it. Using a fresh time.Now() after validation
	// would add the validation latency back onto a short DS lease; anchoring
	// both to observedAt makes each insertion expire at a fixed point rather
	// than restarting the lease (GHSA-mqfw-f48p-2vc8).
	observedAt := time.Now()
	leaseDeadline := observedAt.Add(time.Duration(nsInfo.nsTTL) * time.Second)

	// DNSSEC validation for delegation
	newParentDS, err := r.validateDelegation(ctx, rs.req, resp, q, rs.parentDS, rs.servers.Zone)
	if err != nil {
		return nil, err
	}
	r.clearResolutionZoneFailure(rs.req.Question[0], rs.servers.Zone)
	rs.parentDS = newParentDS

	// Bound the lease by the retained DS lifetime. "Has a DS" is separate
	// from "its TTL": a retained DS with TTL 0 legitimately drives the lease
	// to zero, so check the length, not whether minRRSetTTL is positive.
	if len(rs.parentDS) > 0 {
		if dsDeadline := observedAt.Add(time.Duration(minRRSetTTL(rs.parentDS)) * time.Second); dsDeadline.Before(leaseDeadline) {
			leaseDeadline = dsDeadline
		}
	}

	// Inherit the ancestor cut: a descendant delegation can never outlive
	// the shallowest delegation on its path (Phoenix T2). This absolute
	// deadline is stored verbatim (SetUntil), never reconstructed from a
	// duration, so it cannot be re-inflated by scheduling delay.
	// Put the ancestor first so an exactly inherited deadline retains the
	// ancestor's identity rather than being relabelled as the descendant cut.
	childDeadline, childKey := minCut(rs.cutDeadline, rs.cutKey, leaseDeadline, key)
	noteCut(ctx, childDeadline, childKey)

	// Check for parent detection
	nlevel := dns.CountLabel(q.Name)
	if rs.level > nlevel {
		if r.qnameMinCount > 0 && !rs.nomin {
			// Try without minimization
			newRS := &resolveState{
				req:       rs.req,
				servers:   r.rootServers,
				depth:     rs.depth,
				level:     0,
				nomin:     true,
				parentDS:  nil,
				isRoot:    true,
				extra:     rs.extra,
				requestID: rs.requestID,
				work:      rs.work,
			}
			return r.resolve(ctx, newRS)
		}
		return resp, errParentDetection
	}

	// Determine checking disabled state for the downstream NS-address /
	// DS sub-lookups (an insecure delegation must not fail them closed).
	cd := rs.req.CheckingDisabled || len(rs.parentDS) == 0

	// Key the delegation cache on the CLIENT's CD bit only — never on the
	// delegation's own insecure-ness. searchCache always looks up with
	// rs.req.CheckingDisabled (see the resolve() seed), so a proven-insecure
	// delegation reached by a CD=0 query belongs in the CD=0 bucket where
	// that lookup finds it. Folding len(parentDS)==0 into the key would file
	// it under CD=1 instead — and a transient/unvalidated CD=1 delegation
	// (client or internal NS/DS lookup) could then be served to CD=0 queries,
	// silently stripping AD from a genuinely signed zone.
	if cached, err := r.delegations.Get(key); err == nil {
		// Carry the CURRENT referral's deadline into the cached descent.
		// The cached entry may hold a longer lease than the referral we just
		// observed (e.g. it was inserted before the parent shortened its NS
		// TTL); resolveWithCachedNameservers combines this with
		// cached.ExpiresAt so the shortest applicable cut always wins.
		rs.cutDeadline = childDeadline
		rs.cutKey = childKey
		return r.resolveWithCachedNameservers(ctx, rs, cached, key, q, cd)
	}

	if debugLogEnabled() {
		zlog.Debug("Nameserver cache not found", "key", key, "query", dnsutil.FormatQuestion(q), "cd", cd)
	}

	// Check glue records and perform lookups
	authservers, foundv4, foundv6 := r.checkGlueRR(resp, nsInfo.hosts, rs.level)
	authservers.CheckingDisable = cd
	authservers.Zone = q.Name

	if err := r.lookupV4Nss(ctx, q, authservers, key, rs.parentDS, foundv4, nsInfo.hosts, cd, childDeadline); err != nil {
		return nil, err
	}

	if len(authservers.List) == 0 {
		if minimized && rs.level < nlevel {
			rs.advance(minimized)
			rs.isRoot = false
			return r.resolve(ctx, rs)
		}
		r.recordResolutionZoneFailure(ctx, rs.req.Question[0], q.Name, errNoReachableAuth)
		return nil, errNoReachableAuth
	}

	// Cache delegations. Skip when trust anchors are unavailable so a
	// lookup during the outage cannot land an empty-DS entry that later
	// queries would treat as a proven-insecure delegation after recovery.
	if !r.dnssec || r.hasTrustAnchors() {
		// Store the absolute (inherited) deadline verbatim. A past deadline
		// is not cached (SetUntil skips it).
		r.delegations.SetUntil(key, rs.parentDS, authservers, childDeadline)
		if debugLogEnabled() {
			zlog.Debug("Nameserver cache insert", "key", key, "query", dnsutil.FormatQuestion(q), "cd", cd)
		}
	}

	// Start IPv6 lookups in background, bounded by a fixed
	// deadline. The goroutine sleeps defaultTimeout then walks
	// the NS list, so a small-but-finite budget keeps backlogs
	// from building under cold-cache bursts when the request
	// context is gone — an unbounded context.Background here
	// used to leak goroutines and mutate authservers long
	// after the query returned.
	if r.cfg.IPv6Access {
		reqid := requestIDFromContext(ctx)
		work := rs.work
		attemptGuard := middleware.ResolutionAttemptGuardFrom(ctx)
		var releaseWork func()
		if work != nil {
			var retained bool
			releaseWork, retained = work.Retain()
			if !retained {
				// The request tree has already completed. Starting work now
				// would escape its aggregate cap, so skip this optional
				// enrichment job.
				work = nil
			}
		}
		spawn := rs.work == nil || work != nil
		if spawn && r.v6LookupSlots != nil {
			// Non-blocking slot acquire. The pool caps detached V6 jobs
			// GLOBALLY: a partial upstream outage makes every job live out
			// its full timeout while fresh referrals keep arriving, and an
			// unbounded pool then grows at arrival-rate × timeout. This is
			// optional enrichment — shedding it under pressure is strictly
			// better than becoming the pressure. A nil pool (bare test
			// resolvers) disables the cap.
			select {
			case r.v6LookupSlots <- struct{}{}:
			default:
				spawn = false
				if releaseWork != nil {
					releaseWork()
				}
			}
		}
		if spawn {
			detachedBase := dnssec.InheritNSEC3HashMemos(
				context.Background(),
				ctx,
			)
			if middleware.HasClientECS(ctx) {
				detachedBase = middleware.MarkClientECS(detachedBase)
			}
			go func() { //nolint:gosec // G118 - intentionally detached and bounded by the timeout below
				defer func() {
					if r.v6LookupSlots != nil {
						<-r.v6LookupSlots
					}
				}()
				if releaseWork != nil {
					defer releaseWork()
				}
				v6ctx, cancel := context.WithTimeout(detachedBase, 30*time.Second)
				defer cancel()
				// Retain and pin the originating request-tree ledger before
				// detaching. Every referral job then shares one aggregate
				// cap, and the final metric snapshot waits for these jobs
				// without delaying the client response.
				if work != nil {
					v6ctx = middleware.WithRecursionWork(v6ctx, work)
				}
				if attemptGuard != nil {
					v6ctx = middleware.WithResolutionAttemptGuard(v6ctx, attemptGuard)
				}
				v6ctx = context.WithValue(v6ctx, contextKeyRequestID, reqid)
				r.lookupV6Nss(v6ctx, q, authservers, foundv6, nsInfo.hosts, cd)
			}()
		}
	}

	rs.depth--
	if rs.depth <= 0 {
		return nil, errMaxDepth
	}

	// Continue resolution with new servers. Descend the inherited cut
	// deadline so any deeper delegation is bounded by this one.
	rs.servers = authservers
	rs.level = nlevel
	rs.isRoot = false
	rs.cutDeadline = childDeadline
	rs.cutKey = childKey
	return r.resolve(ctx, rs)
}

// validateDelegation performs DNSSEC validation for delegation.
func (r *Resolver) validateDelegation(ctx context.Context, req, resp *dns.Msg, q dns.Question, parentDS []dns.RR, zone string) ([]dns.RR, error) {
	if req.CheckingDisabled {
		// CD=1: the client has opted out of DNSSEC validation.
		// answer() and authority() already wrap their enforcement in
		// this same guard — delegation handling must match, otherwise
		// a CD=1 DS query under a signed parent SERVFAILs instead of
		// simply resolving. Still walk the DS chain so downstream
		// resolution has the child's DS available if validation is
		// later requested (e.g. by a different request on a shared
		// cache). Propagate CD into the internal DS lookups as well
		// so the chain walk itself inherits the opt-out.
		newDSRR, err := r.findDS(ctx, "", q.Name, parentDS, true)
		if err != nil {
			return nil, err
		}
		return newDSRR, nil
	}

	// Fail closed when trust anchors are unavailable. Without a
	// starting anchor, findDS below would happily return an empty
	// DS set for any signer that isn't the root — processDelegation
	// would then cache that empty-DSSet delegation, and once AutoTA
	// recovers the cached entry would still make signed zones look
	// insecure to later CD=false lookups via searchCache.
	if r.dnssec && !r.hasTrustAnchors() {
		return nil, dnssec.ErrTrustAnchorsUnavailable
	}

	effectiveParentDS := parentDS
	parentSigner := strings.ToLower(dns.Fqdn(zone))
	if parentSigner == "" {
		parentSigner = rootzone
	}
	if parentSigner == rootzone && len(effectiveParentDS) == 0 {
		var err error
		effectiveParentDS, err = r.dsRRFromRootKeys(ctx)
		if err != nil {
			return nil, err
		}
	}

	signers := r.findRRSIGSigners(resp, q.Name, false)
	signerFound := len(signers) > 0

	origDSRR := effectiveParentDS
	if !signerFound {
		if !hasSupportedDS(effectiveParentDS) {
			// Parent is insecure (or only has unsupported DS material),
			// so no authenticated delegation proof is possible or needed.
			return parentDS, nil
		}
		newDSRR, _, err := r.authenticatedDelegationDS(ctx, parentSigner, q.Name, effectiveParentDS)
		if err != nil {
			zlog.Warn("DNSSEC verify failed (delegation)", "query", dnsutil.FormatQuestion(q), "error", err.Error())
			return nil, err
		}
		return newDSRR, nil
	}

	// Try each candidate signer (most specific first) until one
	// validates, matching the answer()/authority() pattern. This
	// prevents an injected RRSIG with a plausible ancestor SignerName
	// from steering the DS lookup to the wrong zone.
	var (
		lastErr      error
		settled      bool
		childDS      []dns.RR
		verified     bool
		finalDS      []dns.RR
		chosenSigner string
	)
	for _, signer := range signers {
		if err := dnssec.ValidateSigner(signer, q.Name); err != nil {
			lastErr = err
			continue
		}
		candidateDSRR, err := r.findDS(ctx, signer, q.Name, origDSRR, false)
		if err != nil {
			if isDNSSECWorkError(err) {
				return nil, err
			}
			lastErr = err
			continue
		}
		if len(candidateDSRR) == 0 {
			if r.isZoneSecure(ctx, q.Name, origDSRR, zone) {
				lastErr = dnssec.ErrDSRecords
				continue
			}
			// Insecure for this candidate.
			finalDS = candidateDSRR
			settled = true
			break
		}
		if !hasSupportedDS(candidateDSRR) {
			// Nothing the validator can verify — treat as insecure.
			finalDS = candidateDSRR
			settled = true
			break
		}
		ok, verr := r.verifyDNSSEC(ctx, signer, q.Name, resp, candidateDSRR)
		if verr != nil {
			if isDNSSECWorkError(verr) {
				return nil, verr
			}
			lastErr = verr
			continue
		}
		if !ok {
			// Every DS in the chain used an unsupported digest — RFC
			// 6840 §5.2 says treat the child as insecure.
			finalDS = []dns.RR{}
			settled = true
			break
		}
		childDS = dnsutil.ExtractRRSet(resp.Ns, q.Name, dns.TypeDS)
		finalDS = candidateDSRR
		chosenSigner = signer
		verified = true
		settled = true
		break
	}
	if !settled {
		if lastErr == nil {
			lastErr = dnssec.ErrDSRecords
		}
		return nil, lastErr
	}
	if !verified {
		return finalDS, nil
	}

	// A referral must carry either a signed DS set for the child
	// (secure delegation) or a signed NSEC/NSEC3 record proving the DS
	// does not exist (insecure delegation). Neither present under a
	// signed parent is a downgrade attempt and must fail closed.
	if len(childDS) > 0 {
		return childDS, nil
	}

	// Zone-filter the denial proofs to the validated signer so an
	// attacker-injected NSEC/NSEC3 from an unrelated sibling zone
	// cannot structurally satisfy the delegation check.
	if nsec3Set := dnsutil.FilterRRsToZone(dnsutil.ExtractRRSet(resp.Ns, "", dns.TypeNSEC3), chosenSigner); len(nsec3Set) > 0 {
		if err := dnssec.VerifyDelegationForZoneWithWork(
			q.Name,
			chosenSigner,
			nsec3Set,
			r.dnssecWork(ctx),
		); err != nil {
			zlog.Warn("NSEC3 verify failed (delegation)", "query", dnsutil.FormatQuestion(q), "error", err.Error())
			return nil, err
		}
		return []dns.RR{}, nil
	}

	if nsecSet := dnsutil.FilterRRsToZone(dnsutil.ExtractRRSet(resp.Ns, "", dns.TypeNSEC), chosenSigner); len(nsecSet) > 0 {
		if err := dnssec.VerifyDelegationNSEC(q.Name, nsecSet); err != nil {
			zlog.Warn("NSEC verify failed (delegation)", "query", dnsutil.FormatQuestion(q), "error", err.Error())
			return nil, err
		}
		return []dns.RR{}, nil
	}

	zlog.Warn("Delegation missing DS and NSEC/NSEC3 proof", "query", dnsutil.FormatQuestion(q))
	return nil, dnssec.ErrNSECMissingCoverage
}

// resolveWithCachedNameservers handles resolution with cached nameservers.
func (r *Resolver) resolveWithCachedNameservers(ctx context.Context, rs *resolveState, cached *authority.Delegation, key uint64, q dns.Question, cd bool) (*dns.Msg, error) {
	if debugLogEnabled() {
		zlog.Debug("Nameserver cache hit", "key", key, "query", dnsutil.FormatQuestion(q), "cd", cd)
	}

	if r.equalServers(cached.Servers, rs.servers) {
		// Potential loop, decrease depth faster
		rs.depth -= 10
	} else {
		rs.depth--
	}

	if rs.depth <= 0 {
		return nil, errMaxDepth
	}

	rs.level++
	rs.servers = cached.Servers
	rs.parentDS = cached.DSSet
	rs.isRoot = false
	// Inherit the cached cut's deadline (defensive min, not overwrite) so a
	// delegation established below it cannot outlive it.
	rs.cutDeadline, rs.cutKey = minCut(rs.cutDeadline, rs.cutKey, cached.ExpiresAt, key)
	noteCut(ctx, rs.cutDeadline, rs.cutKey)
	return r.resolve(ctx, rs)
}
