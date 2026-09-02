package reflex

import (
	"context"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

// The replay pass finishes a query the inline pass already scored:
// recording it again would double its contribution, but the response
// wrapper must still install. The replay is the pass that writes, and
// the tracker's amplification feedback comes from that wrapper.
func TestReflexReplayWrapsWithoutScoring(t *testing.T) {
	cfg := &config.Config{ReflexEnabled: true, ReflexThreshold: 0.99}
	r := New(cfg)

	q := new(dns.Msg)
	q.SetQuestion("amp.example.", dns.TypeTXT)

	wrapped := false
	next := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
		_, wrapped = ch.Writer.(*responseWriter)
		ch.Cancel()
	})

	ch := middleware.NewChain([]middleware.Handler{next})
	ch.Reset(mock.NewWriter("udp", "203.0.113.62:5353"), q)
	ch.SetReplay()
	r.ServeDNS(context.Background(), ch)

	if !wrapped {
		t.Fatal("replay pass did not install the response-size wrapper for a high-amp qtype")
	}

	// The replay must not have recorded the query: after one manual
	// record, the replayed IP's score equals a fresh IP's single-record
	// score. A doubled entry would sit above it.
	qtype, reqLen := dns.TypeTXT, 40
	amp := getAmpFactor(qtype)
	replayed := r.tracker.RecordQuery("203.0.113.62", qtype, amp, reqLen)
	fresh := r.tracker.RecordQuery("203.0.113.63", qtype, amp, reqLen)
	if replayed != fresh {
		t.Fatalf("replay pass scored the query: replayed IP score %v, fresh IP score %v", replayed, fresh)
	}
}
