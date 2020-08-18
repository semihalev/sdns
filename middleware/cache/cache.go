// Copyright 2016-2020 The CoreDNS authors and contributors
// Adapted for SDNS usage by Semih Alev.

package cache

import (
	"context"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/waitgroup"
	"golang.org/x/time/rate"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/cache"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/dnsutil"
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

	// resolver wait group
	wg *waitgroup.WaitGroup

	// Testing.
	now func() time.Time
}

// ResponseWriter implement of ctx.ResponseWriter
type ResponseWriter struct {
	middleware.ResponseWriter

	*Cache
}

var debugns bool

func init() {
	middleware.Register(name, func(cfg *config.Config) middleware.Handler {
		return New(cfg)
	})

	_, debugns = os.LookupEnv("SDNS_DEBUGNS")
}

// New return cache
func New(cfg *config.Config) *Cache {
	if cfg.CacheSize < 1024 {
		cfg.CacheSize = 1024
	}

	c := &Cache{
		pcap:    cfg.CacheSize / 2,
		pcache:  cache.New(cfg.CacheSize / 2),
		pttl:    maxTTL,
		minpttl: minTTL,

		ncap:    cfg.CacheSize / 2,
		ncache:  cache.New(cfg.CacheSize / 2),
		nttl:    time.Duration(cfg.Expire) * time.Second,
		minnttl: time.Duration(cfg.Expire) * time.Second,

		rate: cfg.RateLimit,

		wg: waitgroup.New(15 * time.Second),

		now: time.Now,
	}

	return c
}

// Name return middleware name
func (c *Cache) Name() string { return name }

// ServeDNS implements the Handle interface.
func (c *Cache) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	w, req := ch.Writer, ch.Request

	q := req.Question[0]

	if v := dns.ClassToString[q.Qclass]; v == "" {
		ch.Cancel()
		return
	}

	if v := dns.TypeToString[q.Qtype]; v == "" {
		ch.Cancel()
		return
	}

	// check purge query
	if q.Qclass == dns.ClassCHAOS && q.Qtype == dns.TypeNULL {
		if qname, qtype, ok := dnsutil.ParsePurgeQuestion(req); ok {
			c.purge(qname, qtype)
			ch.Next(ctx)
			return
		}
	}

	if debugns && q.Qclass == dns.ClassCHAOS && q.Qtype == dns.TypeHINFO {
		ch.Next(ctx)
		return
	}

	if q.Name != "." && !req.RecursionDesired {
		ch.CancelWithRcode(dns.RcodeServerFailure, false)

		return
	}

	key := cache.Hash(dns.Question{Name: q.Name, Qtype: dns.TypeNULL})

	if !w.Internal() {
		c.wg.Wait(key)
	}

	now := c.now().UTC()

	i, found := c.get(cache.Hash(q, req.CheckingDisabled), now)
	if i != nil && found {
		if !w.Internal() && c.rate > 0 && !i.Limiter.Allow() {
			//no reply to client
			ch.Cancel()
			return
		}

		m := i.toMsg(req, now)
		m = c.additionalAnswer(ctx, m)

		_ = w.WriteMsg(m)
		ch.Cancel()
		return
	}

	if !w.Internal() {
		c.wg.Wait(key)

		c.wg.Add(key)
		defer c.wg.Done(key)
	}

	ch.Writer = &ResponseWriter{ResponseWriter: w, Cache: c}

	ch.Next(ctx)

	ch.Writer = w
}

// WriteMsg implements the ctx.ResponseWriter interface
func (w *ResponseWriter) WriteMsg(res *dns.Msg) error {
	if res.Truncated {
		return w.ResponseWriter.WriteMsg(res)
	}

	if len(res.Question) == 0 {
		return w.ResponseWriter.WriteMsg(res)
	}

	q := res.Question[0]

	if debugns && q.Qclass == dns.ClassCHAOS && q.Qtype == dns.TypeHINFO {
		return w.ResponseWriter.WriteMsg(res)
	}

	key := cache.Hash(q, res.CheckingDisabled)

	mt, _ := response.Typify(res, w.now().UTC())

	// clear additional records
	var answer []dns.RR

	for i := range res.Answer {
		r := res.Answer[i]

		if r.Header().Rrtype == dns.TypeDNAME ||
			strings.EqualFold(res.Question[0].Name, r.Header().Name) {
			answer = append(answer, r)
		}

		if rrsig, ok := r.(*dns.RRSIG); ok {
			if rrsig.TypeCovered == dns.TypeDNAME &&
				!strings.EqualFold(res.Question[0].Name, r.Header().Name) {
				answer = append(answer, r)
			}
		}
	}
	res.Answer = answer

	msgTTL := dnsutil.MinimalTTL(res, mt)
	var duration time.Duration
	if mt == response.OtherError {
		duration = computeTTL(msgTTL, w.minnttl, w.nttl)
	} else {
		duration = computeTTL(msgTTL, w.minpttl, w.pttl)
	}

	if duration > 0 {
		w.set(key, res, mt, duration)
	}

	res = w.additionalAnswer(context.Background(), res)

	return w.ResponseWriter.WriteMsg(res)
}

func (c *Cache) purge(qname string, qtype uint16) {
	q := dns.Question{Name: qname, Qtype: qtype, Qclass: dns.ClassINET}

	key := cache.Hash(q, false)
	c.ncache.Remove(key)
	c.pcache.Remove(key)

	key = cache.Hash(q, true)
	c.ncache.Remove(key)
	c.pcache.Remove(key)
}

// get returns the entry for a key or an error
func (c *Cache) get(key uint64, now time.Time) (*item, bool) {
	if i, ok := c.pcache.Get(key); ok && i.(*item).ttl(now) > 0 {
		return i.(*item), true
	}

	if i, ok := c.ncache.Get(key); ok && i.(*item).ttl(now) > 0 {
		return i.(*item), true
	}

	return nil, false
}

// set adds a new element to the cache. If the element already exists it is overwritten.
func (c *Cache) set(key uint64, msg *dns.Msg, mt response.Type, duration time.Duration) {
	switch mt {
	case response.NoError, response.Delegation, response.NameError, response.NoData:
		i := newItem(msg, c.now(), duration, c.rate)
		c.pcache.Add(key, i)

	case response.OtherError:
		i := newItem(msg, c.now(), duration, c.rate)
		c.ncache.Add(key, i)
	}
}

// GetP returns positive entry for a key
func (c *Cache) GetP(key uint64, req *dns.Msg) (*dns.Msg, *rate.Limiter, error) {
	if i, ok := c.pcache.Get(key); ok && i.(*item).ttl(c.now()) > 0 {
		it := i.(*item)
		msg := it.toMsg(req, c.now())
		return msg, it.Limiter, nil
	}

	return nil, nil, cache.ErrCacheNotFound
}

// GetN returns negative entry for a key
func (c *Cache) GetN(key uint64, req *dns.Msg) (*rate.Limiter, error) {
	if i, ok := c.ncache.Get(key); ok && i.(*item).ttl(c.now()) > 0 {
		it := i.(*item)
		return it.Limiter, nil
	}

	return nil, cache.ErrCacheNotFound
}

// Set adds a new element to the cache. If the element already exists it is overwritten.
func (c *Cache) Set(key uint64, msg *dns.Msg) {
	mt, _ := response.Typify(msg, c.now().UTC())

	msgTTL := dnsutil.MinimalTTL(msg, mt)
	var duration time.Duration
	if mt == response.OtherError {
		duration = computeTTL(msgTTL, c.minnttl, c.nttl)
	} else {
		duration = computeTTL(msgTTL, c.minpttl, c.pttl)
	}

	c.set(key, msg, mt, duration)
}

func (c *Cache) additionalAnswer(ctx context.Context, msg *dns.Msg) *dns.Msg {
	if msg.Question[0].Qtype == dns.TypeCNAME ||
		msg.Question[0].Qtype == dns.TypeDS {
		return msg
	}

	cnameReq := AcquireMsg()
	defer ReleaseMsg(cnameReq)

	cnameReq.SetEdns0(dnsutil.DefaultMsgSize, true)
	cnameReq.CheckingDisabled = msg.CheckingDisabled

	for _, answer := range msg.Answer {
		if answer.Header().Rrtype == msg.Question[0].Qtype {
			//answer found
			return msg
		}

		if answer.Header().Rrtype == dns.TypeCNAME {
			cr := answer.(*dns.CNAME)
			if cr.Target == msg.Question[0].Name {
				return dnsutil.SetRcode(msg, dns.RcodeServerFailure, false)
			}
			cnameReq.SetQuestion(cr.Target, msg.Question[0].Qtype)
		}
	}

	cnameDepth := 10

	if len(cnameReq.Question) > 0 {
	lookup:
		q := cnameReq.Question[0]
		child := false

		key := cache.Hash(q, cnameReq.CheckingDisabled)
		respCname, _, err := c.GetP(key, cnameReq)
		target := cnameReq.Question[0].Name
		if err == nil {
			target, child = searchAdditionalAnswer(msg, respCname)
		} else {
			respCname, err = dnsutil.ExchangeInternal(ctx, cnameReq)
			if err == nil && (len(respCname.Answer) > 0 || len(respCname.Ns) > 0) {
				target, child = searchAdditionalAnswer(msg, respCname)
				if target == msg.Question[0].Name {
					return dnsutil.SetRcode(msg, dns.RcodeServerFailure, false)
				}
			}
		}

		cnameReq.Question[0].Name = target

		cnameDepth--

		if child && cnameDepth > 0 {
			goto lookup
		}
	}

	return msg
}

func searchAdditionalAnswer(msg, res *dns.Msg) (target string, child bool) {
	if msg.AuthenticatedData && !res.AuthenticatedData {
		msg.AuthenticatedData = false
	}

	for _, r := range res.Answer {
		msg.Answer = append(msg.Answer, r)

		if r.Header().Rrtype == dns.TypeCNAME {
			cr := r.(*dns.CNAME)
			target = cr.Target
			child = true
		}
	}

	for _, r1 := range res.Ns {
		dup := false
		for _, r2 := range msg.Ns {
			if dns.IsDuplicate(r1, r2) {
				dup = true
				break
			}
		}

		if !dup {
			msg.Ns = append(msg.Ns, r1)
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

var messagePool sync.Pool

// AcquireMsg returns an empty msg from pool
func AcquireMsg() *dns.Msg {
	v := messagePool.Get()
	if v == nil {
		return &dns.Msg{}
	}
	return v.(*dns.Msg)
}

// ReleaseMsg returns msg to pool
func ReleaseMsg(m *dns.Msg) {
	m.Id = 0
	m.Response = false
	m.Opcode = 0
	m.Authoritative = false
	m.Truncated = false
	m.RecursionDesired = false
	m.RecursionAvailable = false
	m.Zero = false
	m.AuthenticatedData = false
	m.CheckingDisabled = false
	m.Rcode = 0
	m.Compress = false
	m.Question = nil
	m.Answer = nil
	m.Ns = nil
	m.Extra = nil

	messagePool.Put(m)
}

const (
	name = "cache"

	maxTTL = dnsutil.MaximumDefaulTTL
	minTTL = dnsutil.MinimalDefaultTTL
)
