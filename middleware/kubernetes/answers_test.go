package kubernetes

import (
	"fmt"
	"testing"

	"github.com/miekg/dns"
)

// TestAnswerCacheService walks through the answer types Registry
// pre-builds for a regular ClusterIP service: A, AAAA, SRV per port,
// and PTR for each ClusterIP.
func TestAnswerCacheService(t *testing.T) {
	r := NewRegistry()
	r.AddService(&Service{
		Name:       "web",
		Namespace:  "default",
		ClusterIPs: [][]byte{{10, 96, 0, 1}, {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
		IPFamilies: []string{"IPv4", "IPv6"},
		Ports:      []Port{{Name: "https", Port: 443, Protocol: "TCP"}},
	})

	cases := []struct {
		name  string
		qname string
		qtype uint16
		want  uint16 // expected RR type, 0 for empty
	}{
		{"A", "web.default.svc.cluster.local.", dns.TypeA, dns.TypeA},
		{"AAAA", "web.default.svc.cluster.local.", dns.TypeAAAA, dns.TypeAAAA},
		{"SRV", "_https._tcp.web.default.svc.cluster.local.", dns.TypeSRV, dns.TypeSRV},
		{"PTR v4", "1.0.96.10.in-addr.arpa.", dns.TypePTR, dns.TypePTR},
		{"PTR v6", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.", dns.TypePTR, dns.TypePTR},
		{"NODATA TXT", "web.default.svc.cluster.local.", dns.TypeTXT, 0},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rrs, _, ok := r.ResolveQuery(c.qname, c.qtype)
			if !ok {
				t.Fatalf("expected ok=true for %s/%d", c.qname, c.qtype)
			}
			if c.want == 0 {
				if len(rrs) != 0 {
					t.Fatalf("expected empty, got %v", rrs)
				}
				return
			}
			if len(rrs) == 0 {
				t.Fatalf("expected one %d, got empty", c.want)
			}
			if rrs[0].Header().Rrtype != c.want {
				t.Fatalf("expected type %d, got %d", c.want, rrs[0].Header().Rrtype)
			}
		})
	}
}

// TestAnswerCacheExternalName covers the CNAME-for-any-qtype rule for
// ExternalName services: A and AAAA queries must return the CNAME so
// the recursive resolver chases the target.
func TestAnswerCacheExternalName(t *testing.T) {
	r := NewRegistry()
	r.AddService(&Service{
		Name: "ext", Namespace: "default", Type: "ExternalName",
		ExternalName: "example.com",
	})

	for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME} {
		rrs, _, ok := r.ResolveQuery("ext.default.svc.cluster.local.", qt)
		if !ok || len(rrs) != 1 {
			t.Fatalf("qtype %d: expected one CNAME, got ok=%v rrs=%v", qt, ok, rrs)
		}
		cname, ok := rrs[0].(*dns.CNAME)
		if !ok {
			t.Fatalf("qtype %d: expected *dns.CNAME, got %T", qt, rrs[0])
		}
		if cname.Target != "example.com." {
			t.Errorf("qtype %d: expected target example.com., got %s", qt, cname.Target)
		}
	}
}

// TestAnswerCacheHeadless walks the headless-service path: AddService
// seeds an empty answerSet (so a query before endpoints arrive returns
// authoritative NOERROR/NODATA), and SetEndpoints re-cache populates A
// and AAAA.
func TestAnswerCacheHeadless(t *testing.T) {
	r := NewRegistry()
	r.AddService(&Service{Name: "h", Namespace: "default", Headless: true})

	// Before endpoints: cache hit, no records.
	rrs, _, ok := r.ResolveQuery("h.default.svc.cluster.local.", dns.TypeA)
	if !ok {
		t.Fatal("headless service: expected ok=true (NOERROR/NODATA) before endpoints")
	}
	if len(rrs) != 0 {
		t.Fatalf("headless service: expected empty answer before endpoints, got %v", rrs)
	}

	r.SetEndpoints("h", "default", []Endpoint{
		{Addresses: []string{"10.0.0.1"}, Ready: true},
		{Addresses: []string{"10.0.0.2"}, Ready: true},
		{Addresses: []string{"10.0.0.99"}, Ready: false}, // not ready, must be skipped
		{Addresses: []string{"2001:db8::1"}, Ready: true},
	})

	rrs, _, ok = r.ResolveQuery("h.default.svc.cluster.local.", dns.TypeA)
	if !ok || len(rrs) != 2 {
		t.Fatalf("headless A: expected 2 records, got ok=%v rrs=%v", ok, rrs)
	}

	rrs, _, ok = r.ResolveQuery("h.default.svc.cluster.local.", dns.TypeAAAA)
	if !ok || len(rrs) != 1 {
		t.Fatalf("headless AAAA: expected 1 record, got ok=%v rrs=%v", ok, rrs)
	}
}

// TestAnswerCachePodByIP exercises the encoded-IP pod query path and
// the corresponding PTR record.
func TestAnswerCachePodByIP(t *testing.T) {
	r := NewRegistry()
	r.AddPod(&Pod{Name: "p", Namespace: "default", IPs: []string{"10.244.1.10"}})

	rrs, _, ok := r.ResolveQuery("10-244-1-10.default.pod.cluster.local.", dns.TypeA)
	if !ok || len(rrs) != 1 {
		t.Fatalf("pod A: ok=%v rrs=%v", ok, rrs)
	}
	a := rrs[0].(*dns.A)
	if a.A.String() != "10.244.1.10" {
		t.Errorf("expected 10.244.1.10, got %s", a.A.String())
	}

	rrs, _, ok = r.ResolveQuery("10.1.244.10.in-addr.arpa.", dns.TypePTR)
	if !ok || len(rrs) != 1 {
		t.Fatalf("pod PTR: ok=%v rrs=%v", ok, rrs)
	}
}

// TestPodIPv6Aliases verifies a single IPv6 pod address resolves
// under both the canonical compressed encoding (2001-db8--1) and
// the fully expanded encoding (2001-0db8-...-0001), clients are
// allowed to use either, and the old single-key cache could
// NXDOMAIN for the full form even though the pod existed.
func TestPodIPv6Aliases(t *testing.T) {
	r := NewRegistry()
	r.AddPod(&Pod{Name: "p", Namespace: "default", IPs: []string{"2001:db8::1"}})

	cases := []string{
		"2001-db8--1.default.pod.cluster.local.",
		"2001-0db8-0000-0000-0000-0000-0000-0001.default.pod.cluster.local.",
	}
	for _, qname := range cases {
		t.Run(qname, func(t *testing.T) {
			rrs, _, ok := r.ResolveQuery(qname, dns.TypeAAAA)
			if !ok || len(rrs) != 1 {
				t.Fatalf("ok=%v rrs=%v", ok, rrs)
			}
			if rrs[0].Header().Name != qname {
				t.Errorf("Header.Name should match query: want %s, got %s", qname, rrs[0].Header().Name)
			}
		})
	}

	// Removing the pod must drop both aliases.
	r.DeletePod("p", "default")
	for _, qname := range cases {
		if _, _, ok := r.ResolveQuery(qname, dns.TypeAAAA); ok {
			t.Errorf("alias %s should be invalidated after DeletePod", qname)
		}
	}
}

// TestPodCountIgnoresIPMultiplicity verifies Stats() reports one
// pod per (namespace, name) regardless of how many IPs the pod
// has, the old count summed the IP-keyed shard, double-counting
// dual-stack pods.
func TestPodCountIgnoresIPMultiplicity(t *testing.T) {
	r := NewRegistry()
	r.AddPod(&Pod{
		Name: "dual", Namespace: "default",
		IPs: []string{"10.244.1.1", "2001:db8::1"},
	})
	if got := r.Stats()["pods"]; got != 1 {
		t.Errorf("expected 1 pod for one dual-stack pod, got %d", got)
	}

	r.AddPod(&Pod{
		Name: "single", Namespace: "default",
		IPs: []string{"10.244.1.2"},
	})
	if got := r.Stats()["pods"]; got != 2 {
		t.Errorf("expected 2 pods after adding a single-stack pod, got %d", got)
	}
}

// TestSRVAdditionalGlue verifies SRV responses include the target's
// A/AAAA records as Additional glue, both for ClusterIP services
// (target = service FQDN) and headless services (one target per
// ready endpoint hostname). Without the glue the client has to
// issue a follow-up A lookup, which is what the removed standard
// resolver path saved them from doing.
func TestSRVAdditionalGlue(t *testing.T) {
	t.Run("ClusterIP", func(t *testing.T) {
		r := NewRegistry()
		r.AddService(&Service{
			Name: "web", Namespace: "default",
			ClusterIPs: [][]byte{{10, 96, 0, 1}}, IPFamilies: []string{"IPv4"},
			Ports: []Port{{Name: "http", Port: 80, Protocol: "TCP"}},
		})

		_, extra, ok := r.ResolveQuery("_http._tcp.web.default.svc.cluster.local.", dns.TypeSRV)
		if !ok {
			t.Fatal("SRV: expected ok=true")
		}
		if len(extra) != 1 {
			t.Fatalf("SRV extra: expected 1 A glue, got %d (%v)", len(extra), extra)
		}
		a, isA := extra[0].(*dns.A)
		if !isA || a.A.String() != "10.96.0.1" {
			t.Errorf("SRV extra: expected A 10.96.0.1, got %T %v", extra[0], extra[0])
		}
	})

	t.Run("Headless", func(t *testing.T) {
		r := NewRegistry()
		r.AddService(&Service{
			Name: "h", Namespace: "default", Headless: true,
			Ports: []Port{{Name: "http", Port: 80, Protocol: "TCP"}},
		})
		r.SetEndpoints("h", "default", []Endpoint{
			{Addresses: []string{"10.0.0.1"}, Hostname: "web-0", Ready: true},
			{Addresses: []string{"10.0.0.2"}, Hostname: "web-1", Ready: true},
		})

		answers, extra, ok := r.ResolveQuery("_http._tcp.h.default.svc.cluster.local.", dns.TypeSRV)
		if !ok || len(answers) != 2 {
			t.Fatalf("headless SRV: expected 2 answers, got %v", answers)
		}
		if len(extra) != 2 {
			t.Fatalf("headless SRV extra: expected 2 A records, got %d (%v)", len(extra), extra)
		}
		gotIPs := map[string]bool{}
		for _, rr := range extra {
			if a, ok := rr.(*dns.A); ok {
				gotIPs[a.A.String()] = true
			}
		}
		if !gotIPs["10.0.0.1"] || !gotIPs["10.0.0.2"] {
			t.Errorf("headless SRV extra: expected glue for both endpoints, got %v", gotIPs)
		}
	})
}

// TestHeadlessSRVAnonymousPerAddressTarget pins the per-address
// target for anonymous headless endpoints (no Hostname set).
// Each such endpoint must get a distinct SRV target derived from
// its IP so SRV clients get per-pod discovery; collapsing to one
// service-FQDN target was a regression that lost that. The
// dashed-IP labels (10-0-0-1, etc.) must also resolve as A
// records, clients query the SRV target after.
func TestHeadlessSRVAnonymousPerAddressTarget(t *testing.T) {
	r := NewRegistry()
	r.AddService(&Service{
		Name: "h", Namespace: "default", Headless: true,
		Ports: []Port{{Name: "http", Port: 80, Protocol: "TCP"}},
	})
	r.SetEndpoints("h", "default", []Endpoint{
		{Addresses: []string{"10.0.0.1"}, Ready: true},
		{Addresses: []string{"10.0.0.2"}, Ready: true},
		{Addresses: []string{"10.0.0.3"}, Ready: true},
	})

	answers, _, ok := r.ResolveQuery("_http._tcp.h.default.svc.cluster.local.", dns.TypeSRV)
	if !ok || len(answers) != 3 {
		t.Fatalf("no-hostname SRV: expected 3 per-address records, got %d (%v)", len(answers), answers)
	}
	gotTargets := map[string]bool{}
	for _, rr := range answers {
		gotTargets[rr.(*dns.SRV).Target] = true
	}
	for _, want := range []string{
		"10-0-0-1.h.default.svc.cluster.local.",
		"10-0-0-2.h.default.svc.cluster.local.",
		"10-0-0-3.h.default.svc.cluster.local.",
	} {
		if !gotTargets[want] {
			t.Errorf("missing SRV target %s, got %v", want, gotTargets)
		}
	}

	// Each dashed-IP target must resolve as an A record.
	rrs, _, ok := r.ResolveQuery("10-0-0-2.h.default.svc.cluster.local.", dns.TypeA)
	if !ok || len(rrs) != 1 {
		t.Fatalf("dashed-IP target A: ok=%v rrs=%v", ok, rrs)
	}
	if a := rrs[0].(*dns.A).A.String(); a != "10.0.0.2" {
		t.Errorf("dashed-IP A: want 10.0.0.2, got %s", a)
	}
}

// TestHeadlessAnonymousTargetsClearedOnDelete pins the cleanup
// path for the dashed-IP per-address targets that anonymous
// headless endpoints produce. DeleteService (and any path that
// goes through uncacheServiceAnswers) must clear those entries
// alongside the hostnamed ones, otherwise the answer cache holds
// stale 10-0-0-1.<svc-fqdn> records after the service is gone.
func TestHeadlessAnonymousTargetsClearedOnDelete(t *testing.T) {
	r := NewRegistry()
	r.AddService(&Service{Name: "h", Namespace: "default", Headless: true})
	r.SetEndpoints("h", "default", []Endpoint{
		{Addresses: []string{"10.0.0.1"}, Ready: true},
		{Addresses: []string{"10.0.0.2"}, Hostname: "web-0", Ready: true},
	})

	for _, qname := range []string{
		"10-0-0-1.h.default.svc.cluster.local.",
		"web-0.h.default.svc.cluster.local.",
	} {
		if _, _, ok := r.ResolveQuery(qname, dns.TypeA); !ok {
			t.Fatalf("baseline: %s should resolve", qname)
		}
	}

	r.DeleteService("h", "default")

	for _, qname := range []string{
		"10-0-0-1.h.default.svc.cluster.local.",
		"web-0.h.default.svc.cluster.local.",
	} {
		if _, _, ok := r.ResolveQuery(qname, dns.TypeA); ok {
			t.Errorf("%s must be cleared after DeleteService", qname)
		}
	}
}

// TestHeadlessAnonymousTargetsClearedOnTypeChange covers a
// headless-to-non-headless update: the same Service object stops
// being headless on the next informer event. uncacheServiceAnswers
// runs against the previous (headless) entry and must clear the
// dashed-IP per-address targets so they don't outlive the headless
// configuration.
func TestHeadlessAnonymousTargetsClearedOnTypeChange(t *testing.T) {
	r := NewRegistry()
	r.AddService(&Service{Name: "h", Namespace: "default", Headless: true})
	r.SetEndpoints("h", "default", []Endpoint{
		{Addresses: []string{"10.0.0.1"}, Ready: true},
	})
	if _, _, ok := r.ResolveQuery("10-0-0-1.h.default.svc.cluster.local.", dns.TypeA); !ok {
		t.Fatal("baseline: dashed-IP target must resolve while headless")
	}

	// Re-add as a ClusterIP service (no longer headless). The
	// AddService rebuild path goes via uncacheServiceAnswers on
	// the previous record, which must drop the dashed-IP entries.
	r.AddService(&Service{
		Name: "h", Namespace: "default",
		ClusterIPs: [][]byte{{10, 96, 0, 1}}, IPFamilies: []string{"IPv4"},
	})

	if _, _, ok := r.ResolveQuery("10-0-0-1.h.default.svc.cluster.local.", dns.TypeA); ok {
		t.Error("dashed-IP target must be cleared when service stops being headless")
	}
}

// TestHeadlessSRVMixedHostnamesAndAnonymous covers the mixed case:
// hostnamed endpoints get one target per hostname, anonymous
// endpoints get one target per address. Total SRV count = unique
// hostnames + unique anonymous addresses.
func TestHeadlessSRVMixedHostnamesAndAnonymous(t *testing.T) {
	r := NewRegistry()
	r.AddService(&Service{
		Name: "h", Namespace: "default", Headless: true,
		Ports: []Port{{Name: "http", Port: 80, Protocol: "TCP"}},
	})
	r.SetEndpoints("h", "default", []Endpoint{
		{Addresses: []string{"10.0.0.1"}, Hostname: "web-0", Ready: true},
		{Addresses: []string{"10.0.0.2"}, Hostname: "web-1", Ready: true},
		{Addresses: []string{"10.0.0.3"}, Ready: true}, // anonymous → 10-0-0-3 target
		{Addresses: []string{"10.0.0.4"}, Ready: true}, // anonymous → 10-0-0-4 target
	})

	answers, _, ok := r.ResolveQuery("_http._tcp.h.default.svc.cluster.local.", dns.TypeSRV)
	if !ok || len(answers) != 4 {
		t.Fatalf("mixed SRV: expected 4 records (2 hostnames + 2 dashed-IPs), got %d (%v)", len(answers), answers)
	}
	gotTargets := map[string]int{}
	for _, rr := range answers {
		gotTargets[rr.(*dns.SRV).Target]++
	}
	for target, count := range gotTargets {
		if count != 1 {
			t.Errorf("target %s appears %d times, expected 1", target, count)
		}
	}
	for _, want := range []string{
		"web-0.h.default.svc.cluster.local.",
		"web-1.h.default.svc.cluster.local.",
		"10-0-0-3.h.default.svc.cluster.local.",
		"10-0-0-4.h.default.svc.cluster.local.",
	} {
		if gotTargets[want] != 1 {
			t.Errorf("missing SRV target %s", want)
		}
	}
}

// TestExternalNameUsesServiceTTL pins TTL semantics: ExternalName
// records are service-scoped, not pod-scoped, and must use the
// configured service TTL.
func TestExternalNameUsesServiceTTL(t *testing.T) {
	r := NewRegistry()
	r.SetTTLs(60, 7, 30, 30) // service=60, pod=7
	r.AddService(&Service{
		Name: "ext", Namespace: "default", Type: "ExternalName",
		ExternalName: "example.com",
	})

	rrs, _, ok := r.ResolveQuery("ext.default.svc.cluster.local.", dns.TypeCNAME)
	if !ok || len(rrs) != 1 {
		t.Fatalf("ExternalName: ok=%v rrs=%v", ok, rrs)
	}
	if got := rrs[0].Header().Ttl; got != 60 {
		t.Errorf("ExternalName CNAME TTL: want service TTL 60, got %d", got)
	}
}

// TestPerPodRecordSourcedFromEndpointsOnly pins the contract that
// per-pod service-scoped records (web-0.svc.namespace.svc.cluster.local.)
// come from EndpointSlice hostnames + readiness, never from Pod
// state. Pod state can't tell us if the pod is currently a ready
// endpoint, so publishing from AddPod alone risks announcing
// not-ready pods and pods whose Subdomain points at a service that
// no longer backs them via EndpointSlice.
func TestPerPodRecordSourcedFromEndpointsOnly(t *testing.T) {
	r := NewRegistry()
	r.AddService(&Service{Name: "nginx", Namespace: "default", Headless: true})

	// AddPod with Hostname + Subdomain set must NOT publish a
	// per-pod record on its own.
	r.AddPod(&Pod{
		Name: "pod-uid-abc", Namespace: "default",
		Hostname: "web-0", Subdomain: "nginx",
		IPs: []string{"10.244.1.10"},
	})
	if _, _, ok := r.ResolveQuery("web-0.nginx.default.svc.cluster.local.", dns.TypeA); ok {
		t.Fatal("per-pod record must not appear from Pod state alone")
	}

	// A ready EndpointSlice with that hostname publishes the record.
	r.SetEndpoints("nginx", "default", []Endpoint{
		{Addresses: []string{"10.244.1.10"}, Hostname: "web-0", Ready: true},
	})
	rrs, _, ok := r.ResolveQuery("web-0.nginx.default.svc.cluster.local.", dns.TypeA)
	if !ok || len(rrs) != 1 {
		t.Fatalf("after ready EndpointSlice: ok=%v rrs=%v", ok, rrs)
	}

	// Marking the endpoint not-ready must drop the record.
	r.SetEndpoints("nginx", "default", []Endpoint{
		{Addresses: []string{"10.244.1.10"}, Hostname: "web-0", Ready: false},
	})
	if _, _, ok := r.ResolveQuery("web-0.nginx.default.svc.cluster.local.", dns.TypeA); ok {
		t.Error("per-pod record must be invalidated when endpoint goes not-ready")
	}
}

// TestAnswerCacheServiceUpdate verifies that re-adding a service drops
// stale cache entries (changed IPs, removed ports, etc.).
func TestAnswerCacheServiceUpdate(t *testing.T) {
	r := NewRegistry()
	r.AddService(&Service{
		Name: "svc", Namespace: "default",
		ClusterIPs: [][]byte{{10, 96, 0, 1}}, IPFamilies: []string{"IPv4"},
		Ports: []Port{{Name: "http", Port: 80, Protocol: "TCP"}},
	})

	// PTR for old IP should resolve.
	if _, _, ok := r.ResolveQuery("1.0.96.10.in-addr.arpa.", dns.TypePTR); !ok {
		t.Fatal("expected PTR cache hit for old IP")
	}

	// Re-add with a different IP.
	r.AddService(&Service{
		Name: "svc", Namespace: "default",
		ClusterIPs: [][]byte{{10, 96, 0, 2}}, IPFamilies: []string{"IPv4"},
	})

	// Old IP's PTR is gone.
	if _, _, ok := r.ResolveQuery("1.0.96.10.in-addr.arpa.", dns.TypePTR); ok {
		t.Error("expected old IP PTR to be invalidated")
	}
	// New IP works.
	if _, _, ok := r.ResolveQuery("2.0.96.10.in-addr.arpa.", dns.TypePTR); !ok {
		t.Error("expected new IP PTR to resolve")
	}
	// Old port's SRV is gone.
	if _, _, ok := r.ResolveQuery("_http._tcp.svc.default.svc.cluster.local.", dns.TypeSRV); ok {
		t.Error("expected old SRV to be invalidated after port removal")
	}
}

// TestAnswerCacheDelete verifies DeleteService/DeletePod clear the cache.
func TestAnswerCacheDelete(t *testing.T) {
	r := NewRegistry()
	r.AddService(&Service{
		Name: "svc", Namespace: "default",
		ClusterIPs: [][]byte{{10, 96, 0, 5}}, IPFamilies: []string{"IPv4"},
	})
	r.AddPod(&Pod{Name: "p", Namespace: "default", IPs: []string{"10.244.0.5"}})

	r.DeleteService("svc", "default")
	r.DeletePod("p", "default")

	if _, _, ok := r.ResolveQuery("svc.default.svc.cluster.local.", dns.TypeA); ok {
		t.Error("expected service A to be invalidated after delete")
	}
	if _, _, ok := r.ResolveQuery("5.0.96.10.in-addr.arpa.", dns.TypePTR); ok {
		t.Error("expected service PTR to be invalidated after delete")
	}
	if _, _, ok := r.ResolveQuery("10-244-0-5.default.pod.cluster.local.", dns.TypeA); ok {
		t.Error("expected pod A to be invalidated after delete")
	}
}

// TestHeadlessReAddPreservesEndpoints reproduces the regression where
// re-adding (or updating) a headless service wiped its A/AAAA records.
// AddService for a headless service must rebuild from the
// already-stored endpoint set instead of writing an empty answerSet.
func TestHeadlessReAddPreservesEndpoints(t *testing.T) {
	r := NewRegistry()
	r.AddService(&Service{Name: "h", Namespace: "default", Headless: true})
	r.SetEndpoints("h", "default", []Endpoint{
		{Addresses: []string{"10.0.0.1"}, Ready: true},
	})

	rrs, _, ok := r.ResolveQuery("h.default.svc.cluster.local.", dns.TypeA)
	if !ok || len(rrs) != 1 {
		t.Fatalf("baseline: ok=%v len=%d", ok, len(rrs))
	}

	// Re-add the same service (informer UPDATE). The answer must
	// survive, Spec.ClusterIP=None hasn't changed, neither have
	// the endpoints.
	r.AddService(&Service{Name: "h", Namespace: "default", Headless: true})

	rrs, _, ok = r.ResolveQuery("h.default.svc.cluster.local.", dns.TypeA)
	if !ok || len(rrs) != 1 {
		t.Fatalf("after re-add: expected 1 record, got ok=%v len=%d", ok, len(rrs))
	}
}

// TestHeadlessEndpointsBeforeService covers the informer-ordering case
// where EndpointSlice events arrive before the Service event. The
// endpoint shard records the addresses, and the eventual AddService
// must pick them up.
func TestHeadlessEndpointsBeforeService(t *testing.T) {
	r := NewRegistry()

	// EndpointSlice arrives first (out-of-order informers).
	r.SetEndpoints("h", "default", []Endpoint{
		{Addresses: []string{"10.0.0.1"}, Ready: true},
	})

	// Service event arrives later.
	r.AddService(&Service{Name: "h", Namespace: "default", Headless: true})

	rrs, _, ok := r.ResolveQuery("h.default.svc.cluster.local.", dns.TypeA)
	if !ok || len(rrs) != 1 {
		t.Fatalf("late AddService: expected 1 record, got ok=%v len=%d", ok, len(rrs))
	}
}

// TestHeadlessHostnameRecord covers per-endpoint hostnames: an
// EndpointSlice with Hostname="web-0" must produce
// web-0.<service>.<ns>.svc.<domain>. answerable directly.
func TestHeadlessHostnameRecord(t *testing.T) {
	r := NewRegistry()
	r.AddService(&Service{Name: "nginx", Namespace: "default", Headless: true})
	r.SetEndpoints("nginx", "default", []Endpoint{
		{Addresses: []string{"10.244.1.10"}, Hostname: "web-0", Ready: true},
		{Addresses: []string{"10.244.1.11"}, Hostname: "web-1", Ready: true},
	})

	for _, c := range []struct {
		name    string
		qname   string
		wantIPs []string
	}{
		{"web-0", "web-0.nginx.default.svc.cluster.local.", []string{"10.244.1.10"}},
		{"web-1", "web-1.nginx.default.svc.cluster.local.", []string{"10.244.1.11"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			rrs, _, ok := r.ResolveQuery(c.qname, dns.TypeA)
			if !ok || len(rrs) != 1 {
				t.Fatalf("%s: ok=%v len=%d", c.qname, ok, len(rrs))
			}
			a := rrs[0].(*dns.A)
			if a.A.String() != c.wantIPs[0] {
				t.Errorf("%s: got %s, want %s", c.qname, a.A.String(), c.wantIPs[0])
			}
		})
	}

	// Removing web-0 from the endpoint set must drop its hostname
	// record from the cache.
	r.SetEndpoints("nginx", "default", []Endpoint{
		{Addresses: []string{"10.244.1.11"}, Hostname: "web-1", Ready: true},
	})
	if _, _, ok := r.ResolveQuery("web-0.nginx.default.svc.cluster.local.", dns.TypeA); ok {
		t.Error("web-0 hostname record should have been invalidated when its endpoint was removed")
	}
	if _, _, ok := r.ResolveQuery("web-1.nginx.default.svc.cluster.local.", dns.TypeA); !ok {
		t.Error("web-1 should still resolve")
	}
}

// TestHeadlessSRV covers named ports on headless services: SRV must
// be one record per ready endpoint, target = <hostname>.<svc-fqdn>.
// when set (per K8s DNS spec for StatefulSet discovery), and the
// answer must refresh as endpoints change.
func TestHeadlessSRV(t *testing.T) {
	r := NewRegistry()
	r.AddService(&Service{
		Name: "h", Namespace: "default", Headless: true,
		Ports: []Port{{Name: "http", Port: 80, Protocol: "TCP"}},
	})

	// No endpoints yet: SRV must exist (NOERROR) with no records.
	rrs, _, ok := r.ResolveQuery("_http._tcp.h.default.svc.cluster.local.", dns.TypeSRV)
	if !ok {
		t.Fatal("headless SRV before endpoints: expected NOERROR/NODATA")
	}
	if len(rrs) != 0 {
		t.Errorf("expected empty SRV before endpoints, got %v", rrs)
	}

	r.SetEndpoints("h", "default", []Endpoint{
		{Addresses: []string{"10.0.0.1"}, Hostname: "web-0", Ready: true},
		{Addresses: []string{"10.0.0.2"}, Hostname: "web-1", Ready: true},
	})

	rrs, _, ok = r.ResolveQuery("_http._tcp.h.default.svc.cluster.local.", dns.TypeSRV)
	if !ok || len(rrs) != 2 {
		t.Fatalf("headless SRV: expected 2 records (one per endpoint), got ok=%v len=%d", ok, len(rrs))
	}
	wantTargets := map[string]bool{
		"web-0.h.default.svc.cluster.local.": false,
		"web-1.h.default.svc.cluster.local.": false,
	}
	for _, rr := range rrs {
		srv := rr.(*dns.SRV)
		if srv.Port != 80 {
			t.Errorf("SRV port: want 80, got %d", srv.Port)
		}
		if _, ok := wantTargets[srv.Target]; !ok {
			t.Errorf("unexpected SRV target: %s", srv.Target)
			continue
		}
		wantTargets[srv.Target] = true
	}
	for target, seen := range wantTargets {
		if !seen {
			t.Errorf("missing SRV target: %s", target)
		}
	}

	// Endpoints change: SRV must refresh.
	r.SetEndpoints("h", "default", []Endpoint{
		{Addresses: []string{"10.0.0.3"}, Hostname: "web-0", Ready: true},
	})
	rrs, _, _ = r.ResolveQuery("_http._tcp.h.default.svc.cluster.local.", dns.TypeSRV)
	if len(rrs) != 1 {
		t.Fatalf("after SetEndpoints shrink: expected 1 SRV, got %d", len(rrs))
	}
}

// TestHeadlessDeleteClearsEndpoints reproduces the regression where
// DeleteService left the endpoint shard intact, so a recreate
// resurrected stale endpoint records via cacheServiceAnswers's
// rebuild-from-endpoints path. Delete must wipe the endpoint shard
// entry too.
func TestHeadlessDeleteClearsEndpoints(t *testing.T) {
	r := NewRegistry()
	r.AddService(&Service{Name: "h", Namespace: "default", Headless: true})
	r.SetEndpoints("h", "default", []Endpoint{
		{Addresses: []string{"10.0.0.1"}, Ready: true},
	})

	r.DeleteService("h", "default")

	// GetEndpoints must be empty after delete.
	if eps := r.GetEndpoints("h", "default"); len(eps) != 0 {
		t.Errorf("expected endpoint shard cleared after DeleteService, got %d endpoints", len(eps))
	}

	// Recreate the service. With the bug, the old endpoint comes
	// back. With the fix, the cache is empty until new
	// SetEndpoints arrives.
	r.AddService(&Service{Name: "h", Namespace: "default", Headless: true})

	rrs, _, ok := r.ResolveQuery("h.default.svc.cluster.local.", dns.TypeA)
	if !ok {
		t.Fatal("recreated headless service should still answer (NOERROR/NODATA)")
	}
	if len(rrs) != 0 {
		t.Errorf("recreated headless service must not surface stale endpoints, got %v", rrs)
	}
}

// TestDeleteServiceClearsEndpointsWithoutPriorAdd reproduces the
// regression where DeleteService returned early when no Service
// entry was registered, leaving any endpoints-before-Service state
// behind for a later re-AddService to resurrect. The endpoint
// cleanup must run unconditionally.
func TestDeleteServiceClearsEndpointsWithoutPriorAdd(t *testing.T) {
	r := NewRegistry()

	// EndpointSlice arrives first.
	r.SetEndpoints("h", "default", []Endpoint{
		{Addresses: []string{"10.0.0.1"}, Ready: true},
	})

	// Service-delete arrives before any matching AddService.
	r.DeleteService("h", "default")

	if eps := r.GetEndpoints("h", "default"); len(eps) != 0 {
		t.Errorf("expected endpoint shard cleared, got %d endpoints", len(eps))
	}

	// A later AddService for the same service must start clean,
	// the cached endpoints from before the delete are stale and
	// must not be revived.
	r.AddService(&Service{Name: "h", Namespace: "default", Headless: true})

	rrs, _, ok := r.ResolveQuery("h.default.svc.cluster.local.", dns.TypeA)
	if !ok {
		t.Fatal("recreated headless service should answer NOERROR/NODATA")
	}
	if len(rrs) != 0 {
		t.Errorf("expected empty answer, got %v", rrs)
	}
}

// TestExternalNameFallback verifies the cache fallback path returns
// the CNAME for any qtype (A, AAAA, TXT, ANY) so ExternalName
// services keep behaving like aliases, the recursive resolver below
// us follows the CNAME chain instead of seeing an empty NOERROR.
func TestExternalNameFallback(t *testing.T) {
	r := NewRegistry()
	r.AddService(&Service{
		Name: "ext", Namespace: "default", Type: "ExternalName",
		ExternalName: "example.com",
	})

	for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeTXT, dns.TypeMX} {
		t.Run(dns.TypeToString[qt], func(t *testing.T) {
			rrs, _, ok := r.ResolveQuery("ext.default.svc.cluster.local.", qt)
			if !ok || len(rrs) != 1 {
				t.Fatalf("qtype %d: expected one CNAME, got ok=%v rrs=%v", qt, ok, rrs)
			}
			if cname, isCNAME := rrs[0].(*dns.CNAME); !isCNAME || cname.Target != "example.com." {
				t.Fatalf("qtype %d: expected CNAME→example.com., got %T %v", qt, rrs[0], rrs[0])
			}
		})
	}
}

// TestAnswerCacheANY covers TypeANY: the cache must return every RR
// it has for the name, not silently drop them as it did under the
// old exact-qtype dispatch.
func TestAnswerCacheANY(t *testing.T) {
	r := NewRegistry()
	r.AddService(&Service{
		Name: "svc", Namespace: "default",
		ClusterIPs: [][]byte{{10, 96, 0, 1}, {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
		IPFamilies: []string{"IPv4", "IPv6"},
	})

	rrs, _, ok := r.ResolveQuery("svc.default.svc.cluster.local.", dns.TypeANY)
	if !ok {
		t.Fatal("ANY: expected ok=true")
	}
	// Want at least one A and one AAAA in the union.
	var sawA, sawAAAA bool
	for _, rr := range rrs {
		switch rr.(type) {
		case *dns.A:
			sawA = true
		case *dns.AAAA:
			sawAAAA = true
		}
	}
	if !sawA || !sawAAAA {
		t.Errorf("ANY: expected A+AAAA in union, got %v", rrs)
	}
}

// TestSetEndpointsReusesUnchangedHostnameRRs pins the per-hostname
// incremental contract: when one pod changes, hostnames whose
// ready address set is unchanged must keep the SAME *dns.A pointer
// across rebuilds. The materialise step always rewrites the
// answerSet wrapper struct (it's a tiny allocation), but the
// inner RR pointers, the records that carry the actual IP / name
// / TTL, are reused so a 1000-pod rollout step doesn't re-allocate
// 1000 *dns.A records per event.
func TestSetEndpointsReusesUnchangedHostnameRRs(t *testing.T) {
	r := NewRegistry()
	r.AddService(&Service{Name: "h", Namespace: "default", Headless: true})

	r.SetEndpoints("h", "default", []Endpoint{
		{Addresses: []string{"10.0.0.1"}, Hostname: "web-0", Ready: true},
		{Addresses: []string{"10.0.0.2"}, Hostname: "web-1", Ready: true},
	})

	web0Before, _, _ := r.ResolveQuery("web-0.h.default.svc.cluster.local.", dns.TypeA)
	if len(web0Before) != 1 {
		t.Fatalf("web-0 baseline: expected 1 A, got %v", web0Before)
	}
	web0RRBefore := web0Before[0]

	// Apply a second SetEndpoints: web-0 unchanged, web-1 removed,
	// web-2 added.
	r.SetEndpoints("h", "default", []Endpoint{
		{Addresses: []string{"10.0.0.1"}, Hostname: "web-0", Ready: true},
		{Addresses: []string{"10.0.0.3"}, Hostname: "web-2", Ready: true},
	})

	web0After, _, _ := r.ResolveQuery("web-0.h.default.svc.cluster.local.", dns.TypeA)
	if len(web0After) != 1 {
		t.Fatalf("web-0 after: expected 1 A, got %v", web0After)
	}
	if web0RRBefore != web0After[0] {
		t.Errorf("web-0's *dns.A pointer was reallocated despite unchanged address set: before=%p after=%p",
			web0RRBefore, web0After[0])
	}

	if rrs, _, ok := r.ResolveQuery("web-1.h.default.svc.cluster.local.", dns.TypeA); ok && len(rrs) > 0 {
		t.Errorf("web-1 must be cleared after removal, got %v", rrs)
	}
	if rrs, _, ok := r.ResolveQuery("web-2.h.default.svc.cluster.local.", dns.TypeA); !ok || len(rrs) != 1 {
		t.Errorf("web-2 must resolve after add, got ok=%v rrs=%v", ok, rrs)
	}

	// Sanity: aggregate refreshed.
	rrs, _, _ := r.ResolveQuery("h.default.svc.cluster.local.", dns.TypeA)
	if len(rrs) != 2 {
		t.Errorf("aggregate A: expected 2 records, got %d", len(rrs))
	}
}

// TestSetEndpointsRewritesChangedHostname is the inverse contract:
// when a hostname's ready address set changes, the cache entry
// MUST be rewritten, pointer identity should differ.
func TestSetEndpointsRewritesChangedHostname(t *testing.T) {
	r := NewRegistry()
	r.AddService(&Service{Name: "h", Namespace: "default", Headless: true})

	r.SetEndpoints("h", "default", []Endpoint{
		{Addresses: []string{"10.0.0.1"}, Hostname: "web-0", Ready: true},
	})

	peek := func(qname string) *answerSet {
		shard := r.getAnswerShard(qname)
		shard.mu.RLock()
		defer shard.mu.RUnlock()
		return shard.entries[qname]
	}

	before := peek("web-0.h.default.svc.cluster.local.")
	if before == nil {
		t.Fatal("web-0 must be cached")
	}

	// web-0's address changes, must rewrite.
	r.SetEndpoints("h", "default", []Endpoint{
		{Addresses: []string{"10.0.0.99"}, Hostname: "web-0", Ready: true},
	})

	after := peek("web-0.h.default.svc.cluster.local.")
	if after == before {
		t.Error("web-0 cache entry must be rewritten when address set changes")
	}
	if rrs, _, _ := r.ResolveQuery("web-0.h.default.svc.cluster.local.", dns.TypeA); len(rrs) != 1 || rrs[0].(*dns.A).A.String() != "10.0.0.99" {
		t.Errorf("web-0 must resolve to new address: %v", rrs)
	}
}

// TestHeadlessSRVPortNumberChangeReflected pins that a Service
// update which changes a named port's numeric Port (keeping the
// same name and protocol, so the SRV qname stays the same)
// publishes the new port. The materialise step caches *dns.SRV
// pointers by (srvQname, target) for reuse, but a port-number
// edit invalidates that cache, without the port-mismatch check
// queries would keep returning the stale value.
func TestHeadlessSRVPortNumberChangeReflected(t *testing.T) {
	r := NewRegistry()
	r.AddService(&Service{
		Name: "h", Namespace: "default", Headless: true,
		Ports: []Port{{Name: "http", Port: 80, Protocol: "TCP"}},
	})
	r.SetEndpoints("h", "default", []Endpoint{
		{Addresses: []string{"10.0.0.1"}, Hostname: "web-0", Ready: true},
	})

	rrs, _, ok := r.ResolveQuery("_http._tcp.h.default.svc.cluster.local.", dns.TypeSRV)
	if !ok || len(rrs) != 1 {
		t.Fatalf("baseline: ok=%v rrs=%v", ok, rrs)
	}
	if got := rrs[0].(*dns.SRV).Port; got != 80 {
		t.Errorf("baseline SRV port: want 80, got %d", got)
	}

	// Re-add with the same port name+protocol but a new number.
	r.AddService(&Service{
		Name: "h", Namespace: "default", Headless: true,
		Ports: []Port{{Name: "http", Port: 8080, Protocol: "TCP"}},
	})

	rrs, _, ok = r.ResolveQuery("_http._tcp.h.default.svc.cluster.local.", dns.TypeSRV)
	if !ok || len(rrs) != 1 {
		t.Fatalf("after port change: ok=%v rrs=%v", ok, rrs)
	}
	if got := rrs[0].(*dns.SRV).Port; got != 8080 {
		t.Errorf("after port change: SRV port want 8080, got %d", got)
	}
}

// TestHeadlessRebuildReusesAggregateRRPointers pins the
// O(delta)-allocation contract for the aggregate A record: when a
// real EndpointSlice change replaces one pod, the rebuild must
// reuse the *dns.A pointers for every IP that survived the change.
// Without this guarantee a 1000-pod headless service would
// re-allocate ~1000 *dns.A records on every rollout step,
// dominating CPU under high-churn workloads.
//
// The test compares pointer identity of A records before and after
// the rebuild, equal pointers prove the registry took the reuse
// path; differing pointers prove it allocated fresh.
func TestHeadlessRebuildReusesAggregateRRPointers(t *testing.T) {
	r := NewRegistry()
	r.AddService(&Service{Name: "h", Namespace: "default", Headless: true})

	// Seed with three pods.
	r.SetEndpoints("h", "default", []Endpoint{
		{Addresses: []string{"10.0.0.1"}, Hostname: "web-0", Ready: true},
		{Addresses: []string{"10.0.0.2"}, Hostname: "web-1", Ready: true},
		{Addresses: []string{"10.0.0.3"}, Hostname: "web-2", Ready: true},
	})

	prev, _, _ := r.ResolveQuery("h.default.svc.cluster.local.", dns.TypeA)
	prevByIP := map[string]*dns.A{}
	for _, rr := range prev {
		a := rr.(*dns.A)
		prevByIP[a.A.String()] = a
	}

	// Replace web-2 (10.0.0.3) with web-3 (10.0.0.4). web-0 and
	// web-1's RRs MUST be reused.
	r.SetEndpoints("h", "default", []Endpoint{
		{Addresses: []string{"10.0.0.1"}, Hostname: "web-0", Ready: true},
		{Addresses: []string{"10.0.0.2"}, Hostname: "web-1", Ready: true},
		{Addresses: []string{"10.0.0.4"}, Hostname: "web-3", Ready: true},
	})

	next, _, _ := r.ResolveQuery("h.default.svc.cluster.local.", dns.TypeA)
	nextByIP := map[string]*dns.A{}
	for _, rr := range next {
		a := rr.(*dns.A)
		nextByIP[a.A.String()] = a
	}

	for _, ip := range []string{"10.0.0.1", "10.0.0.2"} {
		if prevByIP[ip] != nextByIP[ip] {
			t.Errorf("aggregate A for %s should reuse the previous pointer (prev=%p next=%p)",
				ip, prevByIP[ip], nextByIP[ip])
		}
	}
	if nextByIP["10.0.0.4"] == nil {
		t.Fatal("aggregate must include the new IP 10.0.0.4")
	}
	if _, stillThere := nextByIP["10.0.0.3"]; stillThere {
		t.Error("aggregate must drop the removed IP 10.0.0.3")
	}
}

// TestHeadlessRebuildReusesSRVPointers pins the same O(delta)
// contract for SRV records: hostname-style services carry stable
// targets across rollout steps, and the SRV rebuild must reuse
// the *dns.SRV pointer for every (target, port) pair that
// survived. A 1000-target × 5-port service that changes one pod
// otherwise re-allocates ~5000 *dns.SRV every rebuild.
func TestHeadlessRebuildReusesSRVPointers(t *testing.T) {
	r := NewRegistry()
	r.AddService(&Service{
		Name: "h", Namespace: "default", Headless: true,
		Ports: []Port{{Name: "http", Port: 80, Protocol: "TCP"}},
	})
	r.SetEndpoints("h", "default", []Endpoint{
		{Addresses: []string{"10.0.0.1"}, Hostname: "web-0", Ready: true},
		{Addresses: []string{"10.0.0.2"}, Hostname: "web-1", Ready: true},
	})

	prev, _, _ := r.ResolveQuery("_http._tcp.h.default.svc.cluster.local.", dns.TypeSRV)
	prevByTarget := map[string]*dns.SRV{}
	for _, rr := range prev {
		s := rr.(*dns.SRV)
		prevByTarget[s.Target] = s
	}

	// Add web-2, web-0 and web-1's SRVs must be reused.
	r.SetEndpoints("h", "default", []Endpoint{
		{Addresses: []string{"10.0.0.1"}, Hostname: "web-0", Ready: true},
		{Addresses: []string{"10.0.0.2"}, Hostname: "web-1", Ready: true},
		{Addresses: []string{"10.0.0.3"}, Hostname: "web-2", Ready: true},
	})

	next, _, _ := r.ResolveQuery("_http._tcp.h.default.svc.cluster.local.", dns.TypeSRV)
	nextByTarget := map[string]*dns.SRV{}
	for _, rr := range next {
		s := rr.(*dns.SRV)
		nextByTarget[s.Target] = s
	}

	for _, target := range []string{
		"web-0.h.default.svc.cluster.local.",
		"web-1.h.default.svc.cluster.local.",
	} {
		if prevByTarget[target] != nextByTarget[target] {
			t.Errorf("SRV for %s should reuse previous pointer (prev=%p next=%p)",
				target, prevByTarget[target], nextByTarget[target])
		}
	}
	if nextByTarget["web-2.h.default.svc.cluster.local."] == nil {
		t.Error("SRV rebuild must include the new target web-2")
	}
}

// BenchmarkHeadlessRebuildOneSliceChange measures the per-rebuild
// cost when a large headless service receives a one-pod change
// via the legacy SetEndpoints API (caller passes the full union).
// Realistic for callers that aren't slice-aware; the registry's
// internal diff-against-state.refs keeps RR allocations O(delta).
func BenchmarkHeadlessRebuildOneSliceChange(b *testing.B) {
	r := NewRegistry()
	r.AddService(&Service{
		Name: "h", Namespace: "default", Headless: true,
		Ports: []Port{
			{Name: "http", Port: 80, Protocol: "TCP"},
			{Name: "grpc", Port: 443, Protocol: "TCP"},
		},
	})

	const n = 1000
	base := make([]Endpoint, n)
	for i := 0; i < n; i++ {
		base[i] = Endpoint{
			Addresses: []string{fmt.Sprintf("10.0.%d.%d", i/256, i%256)},
			Hostname:  fmt.Sprintf("web-%d", i),
			Ready:     true,
		}
	}
	r.SetEndpoints("h", "default", base)

	// Mutate one endpoint per iteration; rest stay identical.
	mutated := make([]Endpoint, n)
	copy(mutated, base)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		idx := i % n
		mutated[idx] = Endpoint{
			Addresses: []string{fmt.Sprintf("10.99.%d.%d", i/256, i%256)},
			Hostname:  fmt.Sprintf("web-%d", idx),
			Ready:     true,
		}
		r.SetEndpoints("h", "default", mutated)
	}
}

// BenchmarkHeadlessApplyOneSlice measures the per-event cost on
// the live client path: one EndpointSlice changes one pod in a
// service backed by 100 slices x 10 endpoints each (1000 total).
// ApplyEndpointSlice updates state O(slice size); MaterialiseHeadless
// rebuilds the answer cache O(state size) but only the dirty
// dimensions allocate. This is the true rollout-step shape,
// alloc cost tracks slice size, not total endpoint count.
func BenchmarkHeadlessApplyOneSlice(b *testing.B) {
	r := NewRegistry()
	r.AddService(&Service{
		Name: "h", Namespace: "default", Headless: true,
		Ports: []Port{
			{Name: "http", Port: 80, Protocol: "TCP"},
			{Name: "grpc", Port: 443, Protocol: "TCP"},
		},
	})

	const slices = 100
	const perSlice = 10
	for s := 0; s < slices; s++ {
		eps := make([]Endpoint, perSlice)
		for i := 0; i < perSlice; i++ {
			pod := s*perSlice + i
			eps[i] = Endpoint{
				Addresses: []string{fmt.Sprintf("10.0.%d.%d", pod/256, pod%256)},
				Hostname:  fmt.Sprintf("web-%d", pod),
				Ready:     true,
			}
		}
		r.ApplyEndpointSlice("h", "default", fmt.Sprintf("h-%d", s), eps)
	}
	r.MaterialiseHeadless("h", "default")

	target := make([]Endpoint, perSlice)
	copy(target, make([]Endpoint, perSlice))

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// Touch slice 0; replace its first endpoint.
		s := 0
		copy(target, []Endpoint{})
		for j := 0; j < perSlice; j++ {
			pod := s*perSlice + j
			addr := fmt.Sprintf("10.0.%d.%d", pod/256, pod%256)
			if j == 0 {
				addr = fmt.Sprintf("10.99.%d.%d", i/256, i%256)
			}
			target[j] = Endpoint{
				Addresses: []string{addr},
				Hostname:  fmt.Sprintf("web-%d", pod),
				Ready:     true,
			}
		}
		r.ApplyEndpointSlice("h", "default", "h-0", target)
		r.MaterialiseHeadless("h", "default")
	}
}

// TestAnswerCacheUnknown verifies unknown names return ok=false so
// ServeDNS passes the query downstream rather than synthesising
// authoritative NXDOMAIN.
func TestAnswerCacheUnknown(t *testing.T) {
	r := NewRegistry()
	if _, _, ok := r.ResolveQuery("nope.default.svc.cluster.local.", dns.TypeA); ok {
		t.Error("expected ok=false for unknown service")
	}
	if _, _, ok := r.ResolveQuery("not-a-cluster-name.example.com.", dns.TypeA); ok {
		t.Error("expected ok=false for non-cluster name")
	}
}
