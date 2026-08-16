package server

import (
	"context"
	"testing"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

type recursionWorkProbe struct {
	ledger *middleware.RecursionWorkLedger
	err    error
}

func (p *recursionWorkProbe) Name() string { return "recursion-work-probe" }

func (p *recursionWorkProbe) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	p.err = middleware.DebitRecursionWork(ctx, middleware.RecursionWorkOutboundQuery)
	p.ledger = middleware.RecursionWorkFrom(ctx)

	resp := new(dns.Msg)
	resp.SetReply(ch.Request.Msg())
	_ = ch.Writer.WriteMsg(resp)
	ch.Cancel()
}

func TestServeDNSUsesPipelineRecursionWorkPolicy(t *testing.T) {
	middleware.Reset()
	t.Cleanup(middleware.Reset)

	cfg := &config.Config{
		RecursionFirewall: config.RecursionFirewallConfig{
			Mode:               config.RecursionFirewallModeEnforce,
			MaxOutboundQueries: 3,
			MaxInternalQueries: 2,
		},
	}
	probe := new(recursionWorkProbe)
	middleware.Register(probe.Name(), func(*config.Config) middleware.Handler {
		return probe
	})
	middleware.Setup(cfg)

	beforeCount, beforeSum := recursionFanoutHistogram(t)
	s := New(cfg)
	if s.pipeline != middleware.GlobalPipeline() {
		t.Fatal("server did not retain the configured global pipeline")
	}

	req := new(dns.Msg)
	req.SetQuestion("entrypoint.example.", dns.TypeA)
	req.RecursionDesired = true
	writer := mock.NewWriter("udp", "192.0.2.1:53000")
	s.ServeMsg(context.Background(), writer, req)

	if probe.err != nil {
		t.Fatalf("probe debit failed: %v", probe.err)
	}
	if probe.ledger == nil {
		t.Fatal("server entrypoint did not establish a recursion-work ledger")
	}
	snapshot := probe.ledger.Snapshot()
	if snapshot.Mode != middleware.RecursionWorkEnforce ||
		snapshot.MaxOutboundQueries != 3 ||
		snapshot.MaxInternalQueries != 2 ||
		snapshot.OutboundQueries != 1 {
		t.Fatalf("server ledger snapshot = %+v, want enforce limits 3/2 and one outbound debit", snapshot)
	}
	if !writer.Written() || writer.Msg().Rcode != dns.RcodeSuccess {
		t.Fatalf("server response = %#v, want NOERROR", writer.Msg())
	}

	afterCount, afterSum := recursionFanoutHistogram(t)
	if got := afterCount - beforeCount; got != 1 {
		t.Fatalf("fanout observations = %d, want exactly one for the client tree", got)
	}
	if got := afterSum - beforeSum; got != 1 {
		t.Fatalf("fanout sum delta = %v, want one outbound attempt", got)
	}
}

func TestServeDNSNoRecursiveWorkSkipsLedgerAndFanoutObservation(t *testing.T) {
	cfg := &config.Config{
		RecursionFirewall: config.RecursionFirewallConfig{
			Mode:               config.RecursionFirewallModeShadow,
			MaxOutboundQueries: 3,
			MaxInternalQueries: 2,
		},
	}
	var ledger *middleware.RecursionWorkLedger
	handler := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
		ledger = middleware.RecursionWorkFrom(ctx)
		ch.Cancel()
	})
	s := serverWithHandler(cfg, handler)

	beforeCount, beforeSum := recursionFanoutHistogram(t)
	req := new(dns.Msg)
	req.SetQuestion("local-hit.example.", dns.TypeA)
	s.ServeMsg(context.Background(), mock.NewWriter("udp", "192.0.2.1:53000"), req)
	afterCount, afterSum := recursionFanoutHistogram(t)

	if ledger != nil {
		t.Fatalf("local terminal response created recursion-work ledger %p", ledger)
	}
	if afterCount != beforeCount || afterSum != beforeSum {
		t.Fatalf("no-work request changed fanout histogram count/sum from %d/%v to %d/%v",
			beforeCount, beforeSum, afterCount, afterSum)
	}
}

func recursionFanoutHistogram(t *testing.T) (uint64, float64) {
	t.Helper()

	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather Prometheus metrics: %v", err)
	}
	for _, family := range families {
		if family.GetName() != "dns_recursion_fanout_ratio" {
			continue
		}
		var count uint64
		var sum float64
		for _, metric := range family.Metric {
			if histogram := metric.GetHistogram(); histogram != nil {
				count += histogram.GetSampleCount()
				sum += histogram.GetSampleSum()
			}
		}
		return count, sum
	}
	t.Fatal("dns_recursion_fanout_ratio metric is not registered")
	return 0, 0
}
