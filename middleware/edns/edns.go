package edns

import (
	"context"
	"encoding/hex"
	"sync"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/util"
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
}

// New return edns.
func New(cfg *config.Config) *EDNS {
	return &EDNS{cookiesecret: cfg.CookieSecret, nsidstr: cfg.NSID}
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
		_ = util.NotSupported(w, req)

		ch.Cancel()
		return
	}

	noedns := req.IsEdns0() == nil

	opt, size, cookie, nsid, do := util.SetEdns0(req)
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
		m = util.ClearDNSSEC(m)
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
	} else {
		// EDNS disabled, remove all OPT records
		m = util.ClearOPT(m)
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

func (w *ResponseWriter) setCookie() {
	if w.cookie == "" {
		return
	}

	w.opt.Option = append(w.opt.Option, &dns.EDNS0_COOKIE{
		Code:   dns.EDNS0COOKIE,
		Cookie: util.GenerateServerCookie(w.cookiesecret, w.RemoteIP().String(), w.cookie),
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
