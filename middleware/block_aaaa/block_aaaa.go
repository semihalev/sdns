// Package block_aaaa suppresses client AAAA answers by operator policy.
package block_aaaa

import (
	"context"
	"encoding/binary"
	"errors"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/dnsutil"
	"github.com/semihalev/sdns/internal/metric"
	"github.com/semihalev/sdns/middleware"
)

const name = "block_aaaa"

var blocked = metric.NewCounter(nil, prometheus.CounterOpts{
	Name: "dns_aaaa_blocked_total",
	Help: "Total client AAAA queries answered with policy NODATA",
})

// BlockAAAA answers client IN/AAAA queries before local answers or resolution.
type BlockAAAA struct{}

// New returns nil when client AAAA suppression is disabled, the default.
func New(cfg *config.Config) *BlockAAAA {
	if !cfg.BlockAAAA {
		return nil
	}
	return &BlockAAAA{}
}

// Name returns the registered middleware name.
func (b *BlockAAAA) Name() string { return name }

// ClientOnly keeps suppression out of the internal resolution pipeline.
func (b *BlockAAAA) ClientOnly() bool { return true }

// ServeDNS answers normal client IN/AAAA queries with unsigned NODATA.
func (b *BlockAAAA) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	// Read parsed scalars first: other types and classes must keep the
	// allocation-free wire path through the cache.
	if b == nil || ch.Request.Qtype() != dns.TypeAAAA || ch.Request.Qclass() != dns.ClassINET {
		ch.Next(ctx)
		return
	}
	// Also protect callers that put this handler in an internal chain
	// themselves instead of building the ClientOnly-filtered pipeline.
	if ch.Writer.Internal() || middleware.IsInternal(ctx) {
		ch.Next(ctx)
		return
	}
	if ch.Request.Undecoded() && b.serveWire(ch) {
		return
	}
	ctx, req := ch.Materialize(ctx)
	if req == nil {
		return
	}
	if req.Response || req.Opcode != dns.OpcodeQuery || len(req.Question) != 1 {
		ch.Next(ctx)
		return
	}

	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = false
	resp.AuthenticatedData = false
	resp.RecursionAvailable = true
	dnsutil.PrependEDE(resp, dns.ExtendedErrorCodeOther, "AAAA response suppressed by policy")
	b.write(ch, resp)
}

func (b *BlockAAAA) write(ch *middleware.Chain, resp *dns.Msg) {
	// Count replies only after a successful write. An inline answer cancels
	// here and is never handed off; a replay that first emits it counts once.
	if err := ch.Writer.WriteMsg(resp); err == nil {
		blocked.Inc()
	}
	ch.Cancel()
}

// serveWire uses the existing EDNS byte writer and its transport-owned lease.
// ParseWire admitted one normal QUERY question, with validated optional OPT;
// copying that question preserves the original spelling without decoding.
// Every refusal happens before transport output and takes the Msg fallback.
func (b *BlockAAAA) serveWire(ch *middleware.Chain) bool {
	w, ok := ch.Writer.(middleware.WireWriter)
	if !ok {
		return false
	}
	capability, ok := w.WireReady()
	if !ok {
		return false
	}
	leaser, ok := ch.Writer.(middleware.WireBodyLeaser)
	if !ok {
		return false
	}
	r := ch.Request
	if r.Raw() == nil || r.Opcode() != dns.OpcodeQuery {
		return false
	}
	const text = "AAAA response suppressed by policy"
	size := r.WireQuestionEnd()
	reserve := capability.Reserve
	if r.HasOPT() {
		reserve += 4 + 2 + len(text)
	}
	if capability.MaxSize != 0 && size+reserve > capability.MaxSize {
		return false
	}
	body := leaser.BeginWire(size, reserve)
	if body == nil {
		return false
	}
	body = body[:size]
	clear(body[:12])
	binary.BigEndian.PutUint16(body[:2], r.ID())
	flags := uint16(0x8000 | 0x0080) // QR and RA; AA, AD, TC and RCODE clear
	if r.RD() {
		flags |= 0x0100
	}
	if r.CD() {
		flags |= 0x0010
	}
	binary.BigEndian.PutUint16(body[2:4], flags)
	binary.BigEndian.PutUint16(body[4:6], 1)
	copy(body[12:], r.Raw()[12:size])
	info := middleware.WireInfo{Rcode: dns.RcodeSuccess, HasEDE: true,
		EDECode: dns.ExtendedErrorCodeOther, EDEText: text}
	err := leaser.CommitWire(body, info)
	if errors.Is(err, middleware.ErrWireFallback) {
		leaser.AbortWire()
		return false
	}
	if err == nil {
		blocked.Inc()
	}
	ch.Cancel()
	return true
}
