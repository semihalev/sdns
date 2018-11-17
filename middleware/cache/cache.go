package cache

import (
	"net/http"
	"time"

	rl "github.com/bsm/ratelimit"
	"github.com/miekg/dns"
	"github.com/semihalev/log"
	"github.com/semihalev/sdns/cache"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/ctx"
	"github.com/semihalev/sdns/dnsutil"
	"github.com/semihalev/sdns/doh"
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
	LookupQueue *LQueue

	// Testing.
	now func() time.Time
}

// New return cache
func New(cfg *config.Config) *Cache {
	c := &Cache{
		pcap:        cfg.CacheSize / 2,
		pcache:      cache.New(cfg.CacheSize),
		pttl:        maxTTL,
		minpttl:     minTTL,
		ncap:        cfg.CacheSize / 2,
		ncache:      cache.New(cfg.CacheSize),
		nttl:        time.Duration(cfg.Expire) * time.Second,
		minnttl:     minNTTL,
		rate:        cfg.RateLimit,
		LookupQueue: NewLookupQueue(),
		now:         time.Now,
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

	msg := c.handle("", req)
	if msg == nil {
		dc.NextDNS()
		return
	}

	w.WriteMsg(msg)

	dc.Abort()
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
	if next {
		dc.NextHTTP()
		return
	}

	dc.Abort()
}

func (c *Cache) handle(Net string, req *dns.Msg) *dns.Msg {
	now := c.now().UTC()

	q := req.Question[0]
	key := cache.Hash(q, req.CheckingDisabled)

	c.LookupQueue.Wait(key)

	i, found := c.get(key, now)
	if i != nil && found {
		opt, do := dnsutil.SetEdns0(req)
		if opt.Version() != 0 {
			opt.SetVersion(0)
			opt.SetExtendedRcode(dns.RcodeBadVers)

			return dnsutil.HandleFailed(req, dns.RcodeBadVers, do)
		}

		if c.rate > 0 && i.RateLimit.Limit() {
			return dnsutil.HandleFailed(req, dns.RcodeRefused, do)
		}

		ok := false
		m := i.toMsg(req, now)
		m, ok = c.additionalAnswer(req, m)
		if !ok {
			return nil
		}

		if !do {
			m = dnsutil.ClearDNSSEC(m)
		}
		m = dnsutil.ClearOPT(m)
		opt.SetDo(do)
		m.Extra = append(m.Extra, opt)

		return m
	}

	return nil
}

// Get returns the entry for a key or an error
func (c *Cache) get(key uint64, now time.Time) (*item, bool) {
	if i, ok := c.ncache.Get(key); ok && i.(*item).ttl(now) > 0 {
		return i.(*item), true
	}

	if i, ok := c.pcache.Get(key); ok && i.(*item).ttl(now) > 0 {
		return i.(*item), true
	}

	return nil, false
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

func (c *Cache) additionalAnswer(req, msg *dns.Msg) (*dns.Msg, bool) {
	//check cname response
	answerFound := false

	cnameReq := new(dns.Msg)
	cnameReq.SetEdns0(dnsutil.DefaultMsgSize, true)
	cnameReq.RecursionDesired = true
	cnameReq.CheckingDisabled = req.CheckingDisabled

	for _, answer := range msg.Answer {
		if answer.Header().Rrtype == req.Question[0].Qtype &&
			(req.Question[0].Qtype == dns.TypeA || req.Question[0].Qtype == dns.TypeAAAA) {
			answerFound = true
		}

		if answer.Header().Rrtype == dns.TypeCNAME {
			cr := answer.(*dns.CNAME)
			cnameReq.SetQuestion(cr.Target, req.Question[0].Qtype)
		}
	}

	cnameDepth := 5

	if !answerFound && len(cnameReq.Question) > 0 {
	lookup:
		q := cnameReq.Question[0]
		child := false

		key := cache.Hash(q, cnameReq.CheckingDisabled)
		respCname, _, err := c.GetP(key, cnameReq)
		if err == nil {
			for _, r := range respCname.Answer {
				msg.Answer = append(msg.Answer, dns.Copy(r))

				if r.Header().Rrtype == dns.TypeCNAME {
					cr := r.(*dns.CNAME)
					cnameReq.Question[0].Name = cr.Target
					child = true
				}
			}
		} else {
			return msg, false
		}

		cnameDepth--

		if child && cnameDepth > 0 {
			goto lookup
		}
	}

	return msg, true
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
