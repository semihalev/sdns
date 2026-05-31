package edns

import (
	"context"
	"encoding/hex"
	"net/netip"
	"sync"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/dnsutil"
	"github.com/semihalev/sdns/internal/ecs"
	"github.com/semihalev/sdns/internal/metric"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/zlog/v2"
)

// ednsErrors counts EDNS protocol-level rejections — queries the
// middleware short-circuits before they reach the resolver chain.
// Closed-set "reason" labels keep the cardinality bounded.
var (
	ednsErrors = metric.NewCounterVec(nil, prometheus.CounterOpts{
		Name: "dns_edns_errors_total",
		Help: "EDNS protocol errors that caused the query to be rejected, by reason",
	}, []string{"reason"})

	ednsErrorOpcodeUnsupp = ednsErrors.Register("opcode_unsupported")
	ednsErrorBadVersion   = ednsErrors.Register("bad_version")
)

// responseWriterPool reuses per-query ResponseWriter wrappers. A wrapper
// is alive exactly for the duration of ch.Next in ServeDNS, so the pool
// bounds to the in-flight query count.
var responseWriterPool = sync.Pool{
	New: func() any { return &ResponseWriter{} },
}

// EDNS type.
type EDNS struct {
	cookiesecret string
	nsidstr      string

	// ecsPolicy is built once from cfg.ECS and read every request.
	// nil is a valid value: it means the historical strip-everything
	// behaviour, which is also what `[ecs] enabled = false` (the
	// default) collapses to.
	ecsPolicy *ecs.Policy
}

// New return edns.
func New(cfg *config.Config) *EDNS {
	return &EDNS{
		cookiesecret: cfg.CookieSecret,
		nsidstr:      cfg.NSID,
		ecsPolicy:    buildECSPolicy(cfg),
	}
}

// buildECSPolicy translates the operator's [ecs] config block into a
// reusable *ecs.Policy. Returns nil when the feature is disabled or
// when the config is invalid (fail-closed). Logs the reason in the
// invalid case so the operator sees the typo on the next start.
func buildECSPolicy(cfg *config.Config) *ecs.Policy {
	c := cfg.ECS
	p, err := ecs.Build(
		c.Enabled,
		c.ForwardV4Max, c.ForwardV6Max,
		c.MinScopeV4, c.MinScopeV6,
		c.ClientNetworks,
	)
	if err != nil {
		zlog.Error("ECS: invalid configuration; forwarding disabled",
			zlog.String("error", err.Error()))
		return nil
	}
	return p
}

// (*EDNS).Name name return middleware name.
func (e *EDNS) Name() string { return name }

// ResponseWriter implement of ctx.ResponseWriter.
type ResponseWriter struct {
	middleware.ResponseWriter
	*EDNS

	opt    *dns.OPT
	size   int
	do     bool
	cookie string
	nsid   bool
	noedns bool
	noad   bool
}

// (*EDNS).ServeDNS serveDNS implements the Handle interface.
func (e *EDNS) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	w, req := ch.Writer, ch.Request

	if req.Opcode > 0 {
		ednsErrorOpcodeUnsupp.Inc()
		_ = dnsutil.NotSupported(w, req)

		ch.Cancel()
		return
	}

	noedns := req.IsEdns0() == nil

	// Convert the writer's net.IP to a netip.Addr for the ECS policy
	// check. AddrFromSlice handles v4 vs v6 by length; an unusable
	// address falls through as a zero netip.Addr, which Policy.Allows
	// safely refuses.
	clientAddr, _ := netip.AddrFromSlice(w.RemoteIP())
	if clientAddr.Is4In6() {
		clientAddr = clientAddr.Unmap()
	}
	opt, size, cookie, nsid, do := dnsutil.SetEdns0(req, e.ecsPolicy, clientAddr)
	if opt.Version() != 0 {
		ednsErrorBadVersion.Inc()
		opt.SetVersion(0)

		ch.CancelWithRcode(dns.RcodeBadVers, do)

		return
	}

	switch w.Proto() {
	case "tcp", "doq", "doh":
		size = dns.MaxMsgSize
	}

	if noedns {
		size = dns.MinMsgSize
	}

	rw := responseWriterPool.Get().(*ResponseWriter)
	rw.ResponseWriter = w
	rw.EDNS = e
	rw.opt = opt
	rw.size = size
	rw.do = do
	rw.cookie = cookie
	rw.noedns = noedns
	rw.nsid = nsid
	rw.noad = !req.AuthenticatedData && !do

	ch.Writer = rw
	// Restore via defer so a downstream panic that a higher-up
	// recovery swallows still unwraps this chain before it
	// returns to the pool — otherwise the next request picks
	// up a stale EDNS wrapper.
	defer func() {
		ch.Writer = w
		*rw = ResponseWriter{}
		responseWriterPool.Put(rw)
	}()
	ch.Next(ctx)
}

// (*ResponseWriter).WriteMsg writeMsg implements the ctx.ResponseWriter interface.
func (w *ResponseWriter) WriteMsg(m *dns.Msg) error {
	m.Compress = true

	if !w.do {
		m = dnsutil.ClearDNSSEC(m)
	}

	if !w.noedns {
		// Get or create OPT record
		opt := m.IsEdns0()
		if opt == nil {
			// No OPT in response, use ours
			opt = w.opt
			m.Extra = append(m.Extra, opt)
		}

		// Set common OPT parameters
		opt.SetDo(w.do)
		opt.SetUDPSize(w.opt.UDPSize())

		// Add server options if not already present
		w.setCookie()
		w.setNSID()

		// Only add our options if they're not already in the response OPT
		if opt == w.opt {
			// This is our OPT, options already added by setCookie/setNSID
		} else {
			// This is response OPT, need to merge our options
			opt.Option = append(opt.Option, w.opt.Option...)
		}

		// Strip every EDNS0_SUBNET from the client-facing response.
		// Two leak paths feed into here:
		//   (a) the resolver re-attaches the request OPT (which we
		//       may have mutated to forward ECS upstream) onto the
		//       response, and
		//   (b) the merge above copies w.opt.Option — which contains
		//       our forwarded ECS — onto the response OPT.
		// Either way, the clamped query ECS would otherwise appear
		// in the client's reply (with SourceScope=0, or duplicated
		// alongside any ECS the upstream itself returned). Stripping
		// here is the simplest closure; the cache middleware sits
		// below edns in the writer chain so it still reads the
		// upstream's response ECS before this strip happens.
		opt.Option = stripECS(opt.Option)
	} else {
		// EDNS disabled, remove all OPT records
		m = dnsutil.ClearOPT(m)
	}

	if w.noad {
		m.AuthenticatedData = false
	}

	if w.Proto() == "udp" && udpOverflow(m, w.size) {
		m.Truncated = true
		m.Answer = []dns.RR{}
		m.Ns = []dns.RR{}
		m.AuthenticatedData = false
	}

	return w.ResponseWriter.WriteMsg(m)
}

// stripECS returns opts with every EDNS0_SUBNET entry removed.
// Done in place when the result is the same length (common case:
// nothing to strip) so the typical OPT write doesn't allocate.
func stripECS(opts []dns.EDNS0) []dns.EDNS0 {
	keep := opts[:0]
	for _, o := range opts {
		if _, isECS := o.(*dns.EDNS0_SUBNET); isECS {
			continue
		}
		keep = append(keep, o)
	}
	return keep
}

func (w *ResponseWriter) setCookie() {
	if w.cookie == "" {
		return
	}

	w.opt.Option = append(w.opt.Option, &dns.EDNS0_COOKIE{
		Code:   dns.EDNS0COOKIE,
		Cookie: dnsutil.GenerateServerCookie(w.cookiesecret, w.RemoteIP().String(), w.cookie),
	})
}

func (w *ResponseWriter) setNSID() {
	if w.nsidstr == "" || !w.nsid {
		return
	}

	w.opt.Option = append(w.opt.Option, &dns.EDNS0_NSID{
		Code: dns.EDNS0NSID,
		Nsid: hex.EncodeToString([]byte(w.nsidstr)),
	})
}

const name = "edns"

// udpOverflow reports whether a UDP response would exceed limit bytes
// and therefore needs TC handling.
//
// Earlier iterations of this function used a count-based heuristic
// over a small set of "fixed-size" RR types to skip the Msg.Len()
// call, but no RR type actually has a wire-size upper bound that's
// both tight and useful: owner names can be up to 255 bytes when
// compression doesn't apply, OPT options are open-ended, and names
// inside rdata (CNAME/NS/PTR/MX/DNAME/SRV target) lift even the
// "small" types past any reasonable constant. An under-estimate
// there would let an oversize reply slip out on UDP without TC=1,
// so we just call Msg.Len() — correctness first, and the cost is
// bounded by response size.
func udpOverflow(m *dns.Msg, limit int) bool {
	return m.Len() > limit
}
