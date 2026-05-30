package edns

import (
	"context"
	"encoding/hex"
	"net/netip"
	"sync"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/dnsutil"
	"github.com/semihalev/sdns/internal/ecs"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/zlog/v2"
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
// reusable *ecs.Policy. Returns nil when the feature is disabled so
// SetEdns0 takes the cheap nil-policy fast path.
//
// Validation is fail-closed: any malformed input (bad CIDR in
// client_networks, source ceiling outside [1, 32]/[1, 128], etc.)
// disables the policy entirely and logs the reason. The earlier
// implementation silently dropped bad CIDRs which, if every entry
// failed to parse, collapsed a restrictive `client_networks` list
// into "no list specified = allow everyone" — a quiet fail-open.
// Forwarding off is always a safer fallback than forwarding too much.
func buildECSPolicy(cfg *config.Config) *ecs.Policy {
	c := cfg.ECS
	if !c.Enabled {
		return nil
	}

	v4 := c.ForwardV4Max
	if v4 == 0 {
		v4 = 24
	}
	if v4 > 32 {
		zlog.Error("ECS: forward_v4 out of range; forwarding disabled",
			zlog.Int("value", int(v4)), zlog.Int("max", 32))
		return nil
	}
	v6 := c.ForwardV6Max
	if v6 == 0 {
		v6 = 56
	}
	if v6 > 128 {
		zlog.Error("ECS: forward_v6 out of range; forwarding disabled",
			zlog.Int("value", int(v6)), zlog.Int("max", 128))
		return nil
	}
	mv4 := c.MinScopeV4
	if mv4 == 0 {
		mv4 = v4
	}
	if mv4 > 32 {
		zlog.Error("ECS: min_scope_v4 out of range; forwarding disabled",
			zlog.Int("value", int(mv4)), zlog.Int("max", 32))
		return nil
	}
	mv6 := c.MinScopeV6
	if mv6 == 0 {
		mv6 = v6
	}
	if mv6 > 128 {
		zlog.Error("ECS: min_scope_v6 out of range; forwarding disabled",
			zlog.Int("value", int(mv6)), zlog.Int("max", 128))
		return nil
	}

	nets := make([]netip.Prefix, 0, len(c.ClientNetworks))
	for _, s := range c.ClientNetworks {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			// Fail-closed: a typo'd CIDR (`10.0.0.0/33`) must not
			// collapse the allow-list to empty and re-open the
			// feature to every client. Disable the policy entirely
			// so the operator sees the loud log and fixes the typo.
			zlog.Error("ECS: invalid client_networks CIDR; forwarding disabled",
				zlog.String("entry", s), zlog.String("error", err.Error()))
			return nil
		}
		nets = append(nets, p)
	}

	return &ecs.Policy{
		Enabled:        true,
		ForwardV4Max:   v4,
		ForwardV6Max:   v6,
		ClientNetworks: nets,
		MinScopeV4:     mv4,
		MinScopeV6:     mv6,
	}
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
