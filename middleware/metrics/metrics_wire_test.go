package metrics

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

// TestDomainMetricsStayOnTheWire pins the contract that put domain
// metrics back on the fast path: a wire-born request is counted by
// domain without ever being materialized. The old pre-serve
// materialization parked the cache's byte path for every query the
// moment the option was enabled.
func TestDomainMetricsStayOnTheWire(t *testing.T) {
	m := New(&config.Config{
		DomainMetrics:      true,
		DomainMetricsLimit: 10,
	})

	q := new(dns.Msg)
	q.SetQuestion("Wire.Example.COM.", dns.TypeA)
	q.RecursionDesired = true
	raw, err := q.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	req := new(middleware.Request)
	if !req.ParseWire(raw, time.Now(), nil) {
		t.Fatal("eligible query refused")
	}

	responder := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		resp := new(dns.Msg)
		resp.SetReply(ch.Request.Msg())
		_ = ch.Writer.WriteMsg(resp)
		ch.Cancel()
	})
	// The responder above materializes deliberately (SetReply needs the
	// message); the assertion below therefore uses a second, byte-only
	// serve where nothing in the chain decodes.
	writer := mock.NewWriter("udp", "192.0.2.5:40000")
	ch := middleware.NewChain([]middleware.Handler{m, responder})
	ch.ResetWire(writer, req)
	ch.AllowDirectPack()
	ch.Next(context.Background())
	if !writer.Written() {
		t.Fatal("no response written")
	}
	if atomic.LoadInt32(&m.domainCount) != 1 {
		t.Fatalf("domainCount = %d, want 1", atomic.LoadInt32(&m.domainCount))
	}
	if _, ok := m.domainTracker.Load(strings.ToLower(strings.TrimSuffix("Wire.Example.COM.", "."))); !ok {
		t.Fatal("wire-born query's domain was not tracked")
	}

	// The byte-only pass: the transport answers from raw bytes and the
	// request must come out the far side still undecoded.
	byteResponder := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		if _, err := ch.Writer.Write(raw); err != nil {
			t.Fatalf("raw write: %v", err)
		}
		ch.Cancel()
	})
	req2 := new(middleware.Request)
	if !req2.ParseWire(raw, time.Now(), nil) {
		t.Fatal("eligible query refused")
	}
	writer2 := mock.NewWriter("udp", "192.0.2.6:40000")
	ch2 := middleware.NewChain([]middleware.Handler{m, byteResponder})
	ch2.ResetWire(writer2, req2)
	ch2.AllowDirectPack()
	ch2.Next(context.Background())
	if !writer2.Written() {
		t.Fatal("no response written on the byte pass")
	}
	if !req2.Undecoded() {
		t.Fatal("domain metrics materialized a wire-born request; the name must come from the wire")
	}
}
