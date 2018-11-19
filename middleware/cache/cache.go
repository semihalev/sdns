package cache

import (
	"net/http"
	"strings"
	"time"

	rl "github.com/bsm/ratelimit"
	"github.com/miekg/dns"
	"github.com/semihalev/log"
	"github.com/semihalev/sdns/cache"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/ctx"
	"github.com/semihalev/sdns/dnsutil"
	"github.com/semihalev/sdns/doh"
	"github.com/semihalev/sdns/lqueue"
	"github.com/semihalev/sdns/response"
)

// Cache type
type Cache struct {
	ncache  *cache.Cache
	ncap    int
	nttl    time.Duration
	minnttl time.Duration

	pcache  *cache.Cache
	pcap    int
	pttl    time.Duration
	minpttl time.Duration

	// ratelimit
	rate int

	// resolver queue
	lqueue *lqueue.LQueue

	// Testing.
	now func() time.Time
}

// DNSResponseWriter implement of ctx.ResponseWriter
type DNSResponseWriter struct {
	ctx.ResponseWriter
	*Cache
}

// HTTPResponseWriter implement of ctx.ResponseWriter
type HTTPResponseWriter struct {
	http.ResponseWriter
	*Cache
}

// New return cache
func New(cfg *config.Config) *Cache {
	c := &Cache{
		pcap:    cfg.CacheSize / 2,
		pcache:  cache.New(cfg.CacheSize),
		pttl:    maxTTL,
		minpttl: minTTL,

		ncap:    cfg.CacheSize / 2,
		ncache:  cache.New(cfg.CacheSize),
		nttl:    time.Duration(cfg.Expire) * time.Second,
		minnttl: time.Duration(cfg.Expire) * time.Second,

		rate: cfg.RateLimit,

		lqueue: lqueue.New(),

		now: time.Now,
	}

	return c
}

// Name return middleware name
func (c *Cache) Name() string {
	return "cache"
}

// ServeDNS implements the Handle interface.
func (c *Cache) ServeDNS(dc *ctx.Context) {
	w, req := dc.DNSWriter, dc.DNSRequest

	key := cache.Hash(req.Question[0], req.CheckingDisabled)

	c.lqueue.Wait(key)

	msg := c.handle("", req)
	if msg != nil {
		w.WriteMsg(msg)
		dc.Abort()
		return
	}

	c.lqueue.Add(key)
	defer c.lqueue.Done(key)

	dc.DNSWriter = &DNSResponseWriter{ResponseWriter: w, Cache: c}

	dc.NextDNS()

	dc.DNSWriter = w
}

func (c *Cache) ServeHTTP(dc *ctx.Context) {
	w, r := dc.HTTPWriter, dc.HTTPRequest

	var f func(http.ResponseWriter, *http.Request) bool
	if r.Method == http.MethodGet && r.URL.Query().Get("dns") == "" {
		f = doh.HandleJSON(c.handle)
	} else {
		f = doh.HandleWireFormat(c.handle)
	}

	next := f(w, r)
	if !next {
		dc.Abort()
		return
	}

	dc.NextHTTP()
}

func (c *Cache) handle(Net string, req *dns.Msg) *dns.Msg {
	now := c.now().UTC()

	q := req.Question[0]

	if q.Name != "." && req.RecursionDesired == false {
		return dnsutil.HandleFailed(req, dns.RcodeServerFailure, false)
	}

	key := cache.Hash(q, req.CheckingDisabled)

	i, found := c.get(key, now)
	if i != nil && found {
		if c.rate > 0 && i.RateLimit.Limit() {
			return dnsutil.HandleFailed(req, dns.RcodeRefused, false)
		}

		m := i.toMsg(req, now)
		m = c.additionalAnswer(m)

		return m
	}

	return nil
}

// WriteMsg implements the ctx.ResponseWriter interface
func (w *DNSResponseWriter) WriteMsg(res *dns.Msg) error {
	if res.Truncated {
		return w.ResponseWriter.WriteMsg(res)
	}

	mt, _ := response.Typify(res, w.now().UTC())

	q := res.Question[0]

	key := cache.Hash(q, res.CheckingDisabled)

	// clear additional records
	var answer []dns.RR

	for i := range res.Answer {
		if strings.ToLower(res.Question[0].Name) == strings.ToLower(res.Answer[i].Header().Name) {
			answer = append(answer, res.Answer[i])
		}
	}
	res.Answer = answer

	msgTTL := dnsutil.MinimalTTL(res, mt)
	var duration time.Duration
	if mt == response.NameError || mt == response.NoData || mt == response.OtherError {
		duration = computeTTL(msgTTL, w.minnttl, w.nttl)
	} else {
		duration = computeTTL(msgTTL, w.minpttl, w.pttl)
	}

	if duration > 0 {
		w.set(key, res, mt, duration)
	}

	// Apply capped TTL to this reply to avoid jarring TTL experience 1799 -> 8 (e.g.)
	ttl := uint32(duration.Seconds())
	for i := range res.Answer {
		res.Answer[i].Header().Ttl = ttl
	}
	for i := range res.Ns {
		res.Ns[i].Header().Ttl = ttl
	}
	for i := range res.Extra {
		if res.Extra[i].Header().Rrtype != dns.TypeOPT {
			res.Extra[i].Header().Ttl = ttl
		}
	}

	res = w.additionalAnswer(res)

	return w.ResponseWriter.WriteMsg(res)
}

// get returns the entry for a key or an error
func (c *Cache) get(key uint64, now time.Time) (*item, bool) {
	if i, ok := c.ncache.Get(key); ok && i.(*item).ttl(now) > 0 {
		return i.(*item), true
	}

	if i, ok := c.pcache.Get(key); ok && i.(*item).ttl(now) > 0 {
		return i.(*item), true
	}

	return nil, false
}

// set adds a new element to the cache. If the element already exists it is overwritten.
func (c *Cache) set(key uint64, msg *dns.Msg, mt response.Type, duration time.Duration) {
	switch mt {
	case response.NoError, response.Delegation:
		i := newItem(msg, c.now(), duration, c.rate)
		c.pcache.Add(key, i)

	case response.NameError, response.NoData, response.OtherError:
		i := newItem(msg, c.now(), duration, c.rate)
		c.ncache.Add(key, i)

	default:
		log.Warn("Caching called with not cachable classification", "response", mt)
	}
}

// GetP returns positive entry for a key
func (c *Cache) GetP(key uint64, req *dns.Msg) (*dns.Msg, *rl.RateLimiter, error) {
	if i, ok := c.pcache.Get(key); ok && i.(*item).ttl(c.now()) > 0 {
		it := i.(*item)
		msg := it.toMsg(req, c.now())
		return msg, it.RateLimit, nil
	}

	return nil, nil, cache.ErrCacheNotFound
}

// GetN returns negative entry for a key
func (c *Cache) GetN(key uint64, req *dns.Msg) error {
	if i, ok := c.ncache.Get(key); ok && i.(*item).ttl(c.now()) > 0 {
		return nil
	}

	return cache.ErrCacheNotFound
}

// Set adds a new element to the cache. If the element already exists it is overwritten.
func (c *Cache) Set(key uint64, msg *dns.Msg) {
	mt, _ := response.Typify(msg, c.now().UTC())

	msgTTL := dnsutil.MinimalTTL(msg, mt)
	var duration time.Duration
	if mt == response.NameError || mt == response.NoData || mt == response.OtherError {
		duration = computeTTL(msgTTL, c.minnttl, c.nttl)
	} else {
		duration = computeTTL(msgTTL, c.minpttl, c.pttl)
	}

	switch mt {
	case response.NoError, response.Delegation:
		i := newItem(msg, c.now(), duration, c.rate)
		c.pcache.Add(key, i)

	case response.NameError, response.NoData, response.OtherError:
		i := newItem(msg, c.now(), duration, c.rate)
		c.ncache.Add(key, i)

	default:
		log.Warn("Caching called with not cachable classification", "response", mt)
	}
}

func (c *Cache) additionalAnswer(msg *dns.Msg) *dns.Msg {
	if msg.Question[0].Qtype != dns.TypeA &&
		msg.Question[0].Qtype != dns.TypeAAAA {
		return msg
	}

	cnameReq := new(dns.Msg)
	cnameReq.SetEdns0(dnsutil.DefaultMsgSize, true)
	cnameReq.RecursionDesired = true
	cnameReq.CheckingDisabled = msg.CheckingDisabled

	for _, answer := range msg.Answer {
		if answer.Header().Rrtype == msg.Question[0].Qtype {
			//answer found
			return msg
		}

		if answer.Header().Rrtype == dns.TypeCNAME {
			cr := answer.(*dns.CNAME)
			cnameReq.SetQuestion(cr.Target, msg.Question[0].Qtype)
		}
	}

	cnameDepth := 5

	if len(cnameReq.Question) > 0 {
	lookup:
		q := cnameReq.Question[0]
		child := false

		key := cache.Hash(q, cnameReq.CheckingDisabled)
		respCname, _, err := c.GetP(key, cnameReq)
		if err == nil {
			cnameReq.Question[0].Name, child = searchAdditionalAnswer(msg, respCname)
		} else {
			respCname, err = dnsutil.ExchangeInternal("tcp", cnameReq)
			if err == nil && len(respCname.Answer) > 0 {
				cnameReq.Question[0].Name, child = searchAdditionalAnswer(msg, respCname)
			}
		}

		cnameDepth--

		if child && cnameDepth > 0 {
			goto lookup
		}
	}

	return msg
}

func searchAdditionalAnswer(msg, res *dns.Msg) (target string, child bool) {
	for _, r := range res.Answer {
		msg.Answer = append(msg.Answer, dns.Copy(r))

		if r.Header().Rrtype == dns.TypeCNAME {
			cr := r.(*dns.CNAME)
			target = cr.Target
			child = true
		}
	}

	return
}

func computeTTL(msgTTL, minTTL, maxTTL time.Duration) time.Duration {
	ttl := msgTTL
	if ttl < minTTL {
		ttl = minTTL
	}
	if ttl > maxTTL {
		ttl = maxTTL
	}
	return ttl
}

const (
	maxTTL  = dnsutil.MaximumDefaulTTL
	minTTL  = dnsutil.MinimalDefaultTTL
	maxNTTL = dnsutil.MinimalDefaultTTL * 60
	minNTTL = dnsutil.MinimalDefaultTTL

	defaultCap = 256 * 50 // default capacity of the cache.
)
