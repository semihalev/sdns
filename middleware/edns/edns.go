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
	ch.Next(ctx)
	ch.Writer = w

	// Drop references before returning to the pool so downstream
	// state (the wrapped writer, the request OPT, cookie text) can
	// be collected with the current query.
	*rw = ResponseWriter{}
	responseWriterPool.Put(rw)
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

// estMaxRRBytes is a realistic upper bound on the wire size of a
// typical RR after name compression. A/AAAA/MX/NS/SOA/CNAME/TXT(small)
// all fit comfortably; DNSKEY (~400) and RRSIG (~250) can exceed it, so
// the heuristic falls back to m.Len() for those edge cases.
const estMaxRRBytes = 200

// udpOverflow reports whether a UDP response would exceed limit bytes
// and therefore needs TC handling. It uses a cheap upper-bound check on
// the RR count first so that small responses (hostsfile/cache hits,
// NXDOMAIN/NODATA, single-A answers) never pay the cost of Msg.Len(),
// which packs the whole message with a compression map just to measure.
func udpOverflow(m *dns.Msg, limit int) bool {
	rrCount := len(m.Answer) + len(m.Ns) + len(m.Extra)
	// 12 header + rrCount * worst-case RR size. If that fits, the
	// actual packed size fits for sure.
	if 12+rrCount*estMaxRRBytes <= limit {
		return false
	}
	return m.Len() > limit
}
