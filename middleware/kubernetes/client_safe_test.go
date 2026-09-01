package kubernetes

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

func newTestClient() *Client {
	return &Client{
		registry:        NewRegistry(),
		stopCh:          make(chan struct{}),
		stopped:         make(chan struct{}),
		slicesByService: map[string]*serviceSlices{},
	}
}

// TestSynced asserts the synced bit is false until the client flips it.
func TestSynced(t *testing.T) {
	c := newTestClient()
	if c.Synced() {
		t.Error("expected Synced to return false initially")
	}
	c.synced.Store(true)
	if !c.Synced() {
		t.Error("expected Synced to return true after flip")
	}
}

// TestSafeWrappersHandleBadInput exercises every safe* wrapper with
// objects that the underlying handler will reject (wrong types, nil
// targets). The wrappers must not panic and must leave the registry
// untouched.
func TestSafeWrappersHandleBadInput(t *testing.T) {
	c := newTestClient()

	c.safeServiceAdd("not a service")
	c.safeServiceAdd(nil)
	c.safeServiceUpdate("old", "new")
	c.safeServiceDelete(123)

	c.safeEndpointSliceAdd(struct{}{})
	c.safeEndpointSliceUpdate("old", "new")
	c.safeEndpointSliceDelete(false)

	c.safePodAdd("string")
	c.safePodUpdate(nil, "new")
	c.safePodDelete(struct{}{})

	if got := c.registry.Stats()["services"]; got != 0 {
		t.Errorf("expected empty registry, got %d services", got)
	}
}

// TestSafeWrappersDispatchValidObjects verifies the wrappers forward
// real objects to the underlying handler.
func TestSafeWrappersDispatchValidObjects(t *testing.T) {
	c := newTestClient()

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "svc", Namespace: "default"},
		Spec: corev1.ServiceSpec{
			ClusterIPs: []string{"10.96.0.1"},
			IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol},
			Ports:      []corev1.ServicePort{{Name: "http", Port: 80, Protocol: corev1.ProtocolTCP}},
		},
	}
	c.safeServiceAdd(svc)
	if got := c.registry.Stats()["services"]; got != 1 {
		t.Fatalf("expected 1 service after add, got %d", got)
	}

	c.safeServiceUpdate(svc, svc) // update is a no-op overwrite
	if got := c.registry.Stats()["services"]; got != 1 {
		t.Fatalf("update should leave 1 service, got %d", got)
	}

	c.safeServiceDelete(svc)
	if got := c.registry.Stats()["services"]; got != 0 {
		t.Fatalf("expected service deleted, got %d remaining", got)
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "default"},
		Status: corev1.PodStatus{
			Phase:  corev1.PodRunning,
			PodIP:  "10.244.0.5",
			PodIPs: []corev1.PodIP{{IP: "10.244.0.5"}},
		},
	}
	c.safePodAdd(pod)
	if got := c.registry.Stats()["pods"]; got != 1 {
		t.Fatalf("expected 1 pod, got %d", got)
	}
	c.safePodUpdate(pod, pod)
	c.safePodDelete(pod)
	if got := c.registry.Stats()["pods"]; got != 0 {
		t.Fatalf("expected pod deleted, got %d remaining", got)
	}

	ready := true
	eps := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "svc-abc",
			Namespace: "default",
			Labels:    map[string]string{discoveryv1.LabelServiceName: "svc"},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{"10.0.0.1"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}},
		},
	}
	c.safeEndpointSliceAdd(eps)
	c.safeEndpointSliceUpdate(eps, eps)
	c.safeEndpointSliceDelete(eps)
}

// TestTombstoneUnwrapping covers the DeletedFinalStateUnknown branch
// in the on*Delete handlers, the informer can deliver a tombstone
// when the original object was missed, and the handler must unwrap it
// so deletions still propagate.
func TestTombstoneUnwrapping(t *testing.T) {
	c := newTestClient()

	// Seed a service so the delete has something to remove.
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "svc", Namespace: "default"},
		Spec:       corev1.ServiceSpec{ClusterIPs: []string{"10.96.0.1"}, IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol}},
	}
	c.onServiceAdd(svc)

	tomb := cache.DeletedFinalStateUnknown{Key: "default/svc", Obj: svc}
	c.onServiceDelete(tomb)
	if got := c.registry.Stats()["services"]; got != 0 {
		t.Errorf("expected service deleted via tombstone, got %d remaining", got)
	}

	// Tombstone with a non-service Obj should be rejected without panicking.
	c.onServiceDelete(cache.DeletedFinalStateUnknown{Key: "x", Obj: "not a service"})

	// Pod tombstone path.
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "default"},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning, PodIPs: []corev1.PodIP{{IP: "10.244.0.5"}}},
	}
	c.onPodAdd(pod)
	c.onPodDelete(cache.DeletedFinalStateUnknown{Key: "default/pod", Obj: pod})
	if got := c.registry.Stats()["pods"]; got != 0 {
		t.Errorf("expected pod deleted via tombstone, got %d remaining", got)
	}

	// EndpointSlice tombstone path.
	ready := true
	eps := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "svc-abc",
			Namespace: "default",
			Labels:    map[string]string{discoveryv1.LabelServiceName: "svc"},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{"10.0.0.1"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}},
		},
	}
	c.onEndpointSliceAdd(eps)
	c.onEndpointSliceDelete(cache.DeletedFinalStateUnknown{Key: "default/svc-abc", Obj: eps})
}

// TestMockResponseWriter exercises every method the test mock exposes,
// they're glue for the dns.ResponseWriter / middleware.ResponseWriter
// interfaces and otherwise wouldn't show up in coverage.
func TestMockResponseWriter(t *testing.T) {
	w := &mockResponseWriter{}
	if w.LocalAddr() == nil {
		t.Error("LocalAddr nil")
	}
	if w.RemoteAddr() == nil {
		t.Error("RemoteAddr nil")
	}
	if w.RemoteIP() == nil {
		t.Error("RemoteIP nil")
	}
	if w.Internal() {
		t.Error("Internal should be false")
	}
	if w.Proto() != "udp" {
		t.Errorf("Proto: want udp, got %s", w.Proto())
	}
	if w.Written() {
		t.Error("Written should start false")
	}

	msg := new(dns.Msg)
	msg.SetQuestion("x.", dns.TypeA)
	if err := w.WriteMsg(msg); err != nil {
		t.Fatalf("WriteMsg: %v", err)
	}
	if !w.Written() || w.Msg() == nil {
		t.Error("WriteMsg should set Written and Msg")
	}
	if w.Rcode() != 0 {
		t.Errorf("Rcode: want 0, got %d", w.Rcode())
	}

	wire, err := msg.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	if _, err := w.Write(wire); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Trivial interface conformance methods.
	if err := w.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// TestStaleSliceAggregationCleanup reproduces the regression where
// onServiceDelete cleared the registry but left c.slicesByService
// behind: a recreated service with a new EndpointSlice would
// re-aggregate stale slice contents from before the delete. The
// per-service entry in slicesByService must be wiped on delete.
func TestStaleSliceAggregationCleanup(t *testing.T) {
	c := newTestClient()
	ready := true

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "h", Namespace: "default"},
		Spec: corev1.ServiceSpec{
			ClusterIP:  corev1.ClusterIPNone,
			ClusterIPs: []string{corev1.ClusterIPNone},
		},
	}
	oldSlice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "h-old",
			Namespace: "default",
			Labels:    map[string]string{discoveryv1.LabelServiceName: "h"},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{"10.0.0.1"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}},
		},
	}
	newSlice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "h-new",
			Namespace: "default",
			Labels:    map[string]string{discoveryv1.LabelServiceName: "h"},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{"10.0.0.2"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}},
		},
	}

	c.onServiceAdd(svc)
	c.onEndpointSliceAdd(oldSlice)
	c.onServiceDelete(svc) // <-- must also drop slicesByService["default/h"]
	c.onServiceAdd(svc)
	c.onEndpointSliceAdd(newSlice)

	rrs, _, ok := c.registry.ResolveQuery("h.default.svc.cluster.local.", dns.TypeA)
	if !ok || len(rrs) != 1 {
		t.Fatalf("recreated service: expected one A record, got ok=%v rrs=%v", ok, rrs)
	}
	if a := rrs[0].(*dns.A); a.A.String() != "10.0.0.2" {
		t.Errorf("expected 10.0.0.2 only, got %s", a.A.String())
	}
}

// TestRebuildCoalescesBurst pins the per-service rebuild coalescing:
// a burst of EndpointSlice events for one service must produce far
// fewer rebuilds than events. Without coalescing every event drives
// a full SetEndpoints (aggregate A/AAAA + per-port SRV + per-host
// diff), for a 1000-pod headless StatefulSet with 100 slices, a
// rolling update would O(slices x total endpoints) the registry.
func TestRebuildCoalescesBurst(t *testing.T) {
	c := newTestClient()
	c.queue = newRebuildQueue()
	// Short debounce keeps the test fast but still gives time for
	// the burst to coalesce into a single drain.
	c.rebuildDebounce = 10 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// startRebuildWorker flips running=true synchronously before
	// launching the goroutine, so the producer never races into
	// the inline-rebuild fallback.
	workerDone := c.startRebuildWorker(ctx)
	if !c.queue.running.Load() {
		t.Fatal("startRebuildWorker must flip running synchronously")
	}

	// Seed a headless service so the rebuild has something to write
	// to the registry, otherwise SetEndpoints returns early.
	c.registry.AddService(&Service{Name: "h", Namespace: "default", Headless: true})

	const burst = 100
	for i := 0; i < burst; i++ {
		eps := &discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "h-slice",
				Namespace: "default",
				Labels:    map[string]string{discoveryv1.LabelServiceName: "h"},
			},
			AddressType: discoveryv1.AddressTypeIPv4,
			Endpoints: []discoveryv1.Endpoint{
				{
					Addresses:  []string{net.IPv4(10, 0, 0, byte(i+1)).String()},
					Conditions: discoveryv1.EndpointConditions{Ready: ptrBool(true)},
				},
			},
		}
		c.onEndpointSliceUpdate(eps, eps)
	}

	// Wait long enough for the worker to drain (debounce + slack).
	deadline := time.Now().Add(500 * time.Millisecond)
	var got uint64
	for time.Now().Before(deadline) {
		got = c.Rebuilds()
		if got > 0 && len(c.queue.drain()) == 0 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	got = c.Rebuilds()
	if got == 0 {
		t.Fatal("no rebuilds fired, worker isn't running")
	}
	if got >= burst {
		t.Errorf("expected coalesced rebuilds (<<%d), got %d", burst, got)
	}

	// Final state must reflect the LAST event, coalescing must
	// not lose updates.
	rrs, _, ok := c.registry.ResolveQuery("h.default.svc.cluster.local.", dns.TypeA)
	if !ok || len(rrs) != 1 {
		t.Fatalf("expected one A record from latest slice, got ok=%v rrs=%v", ok, rrs)
	}
	wantIP := net.IPv4(10, 0, 0, byte(burst)).String()
	if got := rrs[0].(*dns.A).A.String(); got != wantIP {
		t.Errorf("expected %s (latest event), got %s", wantIP, got)
	}

	cancel()
	<-workerDone
}

func ptrBool(b bool) *bool { return &b }

// TestFlushRebuildsDrainsBacklog pins the Synced contract: after
// flushRebuilds returns, the registry must reflect every queued
// rebuild. Run calls flushRebuilds before synced.Store(true), so
// any consumer gating on Synced (ServeDNS does, via the middleware)
// sees a fully-rebuilt registry, not a registry where headless
// services NODATA for tens of ms while the worker drains the
// initial-LIST backlog.
func TestFlushRebuildsDrainsBacklog(t *testing.T) {
	c := newTestClient()
	c.queue = newRebuildQueue()
	c.rebuildDebounce = time.Hour // worker won't drain on its own

	c.registry.AddService(&Service{Name: "h", Namespace: "default", Headless: true})

	// Worker is NOT running, scheduleRebuild would normally
	// fall back to inline rebuild. Stage state via slicesByService
	// and queue the rebuild so flush can drain it.
	c.slicesMu.Lock()
	c.slicesByService = map[string]*serviceSlices{
		"default/h": {
			slices: map[string][]Endpoint{
				"h-slice": {{Addresses: []string{"10.0.0.1"}, Ready: true}},
			},
		},
	}
	c.slicesMu.Unlock()
	c.queue.enqueue("default/h")

	if rrs, _, _ := c.registry.ResolveQuery("h.default.svc.cluster.local.", dns.TypeA); len(rrs) != 0 {
		t.Fatal("registry should be empty before flush")
	}

	c.flushRebuilds()

	rrs, _, ok := c.registry.ResolveQuery("h.default.svc.cluster.local.", dns.TypeA)
	if !ok || len(rrs) != 1 {
		t.Fatalf("after flushRebuilds: expected 1 record, got ok=%v rrs=%v", ok, rrs)
	}
	if c.Rebuilds() != 1 {
		t.Errorf("expected 1 rebuild after flush, got %d", c.Rebuilds())
	}
}

// TestFlushRebuildsWaitsForInflight covers the race where the
// worker is mid-rebuild when flush is called. flush must hold
// processingMu, so it waits for the worker's current cycle to
// finish before returning.
func TestFlushRebuildsWaitsForInflight(t *testing.T) {
	c := newTestClient()
	c.queue = newRebuildQueue()

	// Hold processingMu to simulate "worker mid-cycle". flush
	// blocks until we release it.
	c.queue.processingMu.Lock()

	done := make(chan struct{})
	go func() {
		c.flushRebuilds()
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("flushRebuilds returned while processingMu was held, must have waited for in-flight cycle")
	case <-time.After(20 * time.Millisecond):
	}

	c.queue.processingMu.Unlock()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("flushRebuilds didn't return after processingMu released")
	}
}

// TestLateSliceForDeletedServiceRejected pins the UID-tombstone
// contract: an EndpointSlice update whose ownerRef matches a Service
// the client has just observed deleted MUST be dropped, even if the
// recreate hasn't been observed yet. Without this guard the late
// slice would re-populate slicesByService, the worker would push
// stale endpoints into the registry's endpoint shard, and the next
// AddService for the same name would publish the deleted IPs.
func TestLateSliceForDeletedServiceRejected(t *testing.T) {
	c := newTestClient()
	ready := true

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: "h", Namespace: "default", UID: "uid-1",
		},
		Spec: corev1.ServiceSpec{
			ClusterIP:  corev1.ClusterIPNone,
			ClusterIPs: []string{corev1.ClusterIPNone},
		},
	}
	slice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "h-abc",
			Namespace: "default",
			Labels:    map[string]string{discoveryv1.LabelServiceName: "h"},
			OwnerReferences: []metav1.OwnerReference{
				{Kind: "Service", Name: "h", UID: "uid-1"},
			},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{"10.0.0.1"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}},
		},
	}

	c.onServiceAdd(svc)
	c.onEndpointSliceAdd(slice)

	if rrs, _, _ := c.registry.ResolveQuery("h.default.svc.cluster.local.", dns.TypeA); len(rrs) != 1 {
		t.Fatalf("baseline: expected 1 record, got %v", rrs)
	}

	c.onServiceDelete(svc)

	// Verify tombstone was recorded.
	c.slicesMu.Lock()
	tomb, ok := c.tombstones["default/h"]
	c.slicesMu.Unlock()
	if !ok || tomb != "uid-1" {
		t.Fatalf("tombstone not set after delete: ok=%v uid=%q", ok, tomb)
	}

	// Late slice update from the SAME UID arrives, must be
	// rejected. Without the tombstone check this would
	// re-populate slicesByService and trigger a rebuild.
	c.onEndpointSliceUpdate(slice, slice)

	c.slicesMu.Lock()
	stillStaged := c.slicesByService["default/h"]
	c.slicesMu.Unlock()
	if stillStaged != nil {
		t.Errorf("late slice for deleted service should have been rejected, got entry %+v", stillStaged)
	}

	// Recreate with a NEW UID. cacheServiceAnswers must read an
	// empty endpoint shard, no leftover IPs from u1 should
	// surface.
	svc2 := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: "h", Namespace: "default", UID: "uid-2",
		},
		Spec: corev1.ServiceSpec{
			ClusterIP:  corev1.ClusterIPNone,
			ClusterIPs: []string{corev1.ClusterIPNone},
		},
	}
	c.onServiceAdd(svc2)

	rrs, _, ok := c.registry.ResolveQuery("h.default.svc.cluster.local.", dns.TypeA)
	if !ok {
		t.Fatal("recreated service should answer NOERROR/NODATA")
	}
	if len(rrs) != 0 {
		t.Errorf("recreated service must not surface stale endpoints, got %v", rrs)
	}
}

// TestEndpointsBeforeServicePreservesOtherSlicesOnFirstUpdate
// pins the synthetic-seed handover. When EndpointSlices arrive
// before the headless Service event, they're stashed as one
// synthetic contribution on the registry side. The first
// non-synthetic ApplyEndpointSlice retracts that synthetic
// contribution, so unless the Client re-pushes every other
// slice on the AddService path, the other slices' endpoints
// would vanish from A/SRV answers until each one was replayed
// individually.
func TestEndpointsBeforeServicePreservesOtherSlicesOnFirstUpdate(t *testing.T) {
	c := newTestClient()
	ready := true

	mkSlice := func(name, addr string) *discoveryv1.EndpointSlice {
		return &discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name: name, Namespace: "default",
				Labels: map[string]string{discoveryv1.LabelServiceName: "h"},
			},
			AddressType: discoveryv1.AddressTypeIPv4,
			Endpoints: []discoveryv1.Endpoint{
				{Addresses: []string{addr}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}},
			},
		}
	}

	// Endpoints arrive BEFORE the Service add: three slices,
	// each contributing one endpoint.
	c.onEndpointSliceAdd(mkSlice("h-1", "10.0.0.1"))
	c.onEndpointSliceAdd(mkSlice("h-2", "10.0.0.2"))
	c.onEndpointSliceAdd(mkSlice("h-3", "10.0.0.3"))

	// Service event: marks the service as headless.
	c.onServiceAdd(&corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "h", Namespace: "default"},
		Spec: corev1.ServiceSpec{
			ClusterIP:  corev1.ClusterIPNone,
			ClusterIPs: []string{corev1.ClusterIPNone},
		},
	})

	// First post-service update touches just slice h-1.
	c.onEndpointSliceUpdate(mkSlice("h-1", "10.0.0.1"), mkSlice("h-1", "10.0.0.99"))

	// Aggregate must include the new h-1 endpoint AND the
	// surviving h-2 and h-3 endpoints. Without the
	// dirty-on-AddService fix, h-2 and h-3 vanish here.
	rrs, _, ok := c.registry.ResolveQuery("h.default.svc.cluster.local.", dns.TypeA)
	if !ok {
		t.Fatal("expected aggregate A answer")
	}
	got := map[string]bool{}
	for _, rr := range rrs {
		got[rr.(*dns.A).A.String()] = true
	}
	for _, want := range []string{"10.0.0.99", "10.0.0.2", "10.0.0.3"} {
		if !got[want] {
			t.Errorf("missing %s; aggregate: %v", want, got)
		}
	}
	if got["10.0.0.1"] {
		t.Errorf("old h-1 address 10.0.0.1 should have been replaced; aggregate: %v", got)
	}
}

// TestEndpointSliceRelabelClearsOldService pins that an
// EndpointSlice update which changes the service-name label
// retracts the slice's contribution from the old service before
// applying it to the new one. Without this the old service's
// endpoint list keeps the stale entry until something else
// (Service delete/recreate, restart) cleans it up.
func TestEndpointSliceRelabelClearsOldService(t *testing.T) {
	c := newTestClient()
	ready := true

	c.registry.AddService(&Service{Name: "a", Namespace: "default", Headless: true})
	c.registry.AddService(&Service{Name: "b", Namespace: "default", Headless: true})

	oldSlice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name: "slice-1", Namespace: "default",
			Labels: map[string]string{discoveryv1.LabelServiceName: "a"},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{"10.0.0.1"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}},
		},
	}
	c.onEndpointSliceAdd(oldSlice)

	if rrs, _, _ := c.registry.ResolveQuery("a.default.svc.cluster.local.", dns.TypeA); len(rrs) != 1 {
		t.Fatalf("baseline: service a should have one record, got %v", rrs)
	}

	// The same slice object now claims service-name "b".
	newSlice := *oldSlice
	newSlice.Labels = map[string]string{discoveryv1.LabelServiceName: "b"}
	c.onEndpointSliceUpdate(oldSlice, &newSlice)

	if rrs, _, _ := c.registry.ResolveQuery("a.default.svc.cluster.local.", dns.TypeA); len(rrs) != 0 {
		t.Errorf("after relabel: service a must be empty, got %v", rrs)
	}
	if rrs, _, _ := c.registry.ResolveQuery("b.default.svc.cluster.local.", dns.TypeA); len(rrs) != 1 {
		t.Errorf("after relabel: service b must have the endpoint, got %v", rrs)
	}
}

// TestEndpointSliceLabelRemovedClearsOldService covers the case
// where the service-name label is dropped entirely (slice
// orphaned). Old service must lose its contribution; the
// orphaned slice itself does not belong to any new service.
func TestEndpointSliceLabelRemovedClearsOldService(t *testing.T) {
	c := newTestClient()
	ready := true
	c.registry.AddService(&Service{Name: "a", Namespace: "default", Headless: true})

	oldSlice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name: "slice-1", Namespace: "default",
			Labels: map[string]string{discoveryv1.LabelServiceName: "a"},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{"10.0.0.1"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}},
		},
	}
	c.onEndpointSliceAdd(oldSlice)

	newSlice := *oldSlice
	newSlice.Labels = map[string]string{} // label gone
	c.onEndpointSliceUpdate(oldSlice, &newSlice)

	if rrs, _, _ := c.registry.ResolveQuery("a.default.svc.cluster.local.", dns.TypeA); len(rrs) != 0 {
		t.Errorf("orphaned slice should leave service a empty, got %v", rrs)
	}
}

// TestNoOpUpdateSkipsRebuild pins the resourceVersion-only update
// guard: an EndpointSlice update whose payload (addresses,
// hostname, ready, target ref) is byte-identical to the prior
// version must NOT trigger a rebuild. Informers fire UPDATE on
// every metadata bump; without this guard a steady churn of
// such no-op events drives O(N) rebuilds per event for large
// services.
func TestNoOpUpdateSkipsRebuild(t *testing.T) {
	c := newTestClient()
	ready := true
	c.registry.AddService(&Service{Name: "h", Namespace: "default", Headless: true})

	slice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name: "h-slice", Namespace: "default",
			Labels: map[string]string{discoveryv1.LabelServiceName: "h"},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{"10.0.0.1"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}},
		},
	}
	c.onEndpointSliceAdd(slice)
	baseline := c.Rebuilds()
	if baseline == 0 {
		t.Fatal("first add should have rebuilt")
	}

	// Same slice payload, replayed as an UPDATE, must be a no-op.
	for i := 0; i < 50; i++ {
		c.onEndpointSliceUpdate(slice, slice)
	}
	if got := c.Rebuilds(); got != baseline {
		t.Errorf("no-op updates should not rebuild: baseline=%d after=%d", baseline, got)
	}

	// Real change must rebuild.
	changed := *slice
	changed.Endpoints = []discoveryv1.Endpoint{
		{Addresses: []string{"10.0.0.2"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}},
	}
	c.onEndpointSliceUpdate(slice, &changed)
	if got := c.Rebuilds(); got != baseline+1 {
		t.Errorf("real change should rebuild once: baseline=%d after=%d", baseline, got)
	}
}

// TestRecreatedServiceRejectsLateOldSlice pins the Service-first
// recreate path: delete(u1) → add(u2) → late slice(u1). bindServiceUID
// must materialise an entry bound to u2 even though no slices have
// arrived yet, otherwise the cleared tombstone leaves no UID guard
// in place and the late u1 slice would get accepted, staged in
// slicesByService, rebuilt by the worker, and published as fresh
// endpoints under the new headless service.
func TestRecreatedServiceRejectsLateOldSlice(t *testing.T) {
	c := newTestClient()
	ready := true

	svc1 := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: "h", Namespace: "default", UID: "uid-1",
		},
		Spec: corev1.ServiceSpec{
			ClusterIP:  corev1.ClusterIPNone,
			ClusterIPs: []string{corev1.ClusterIPNone},
		},
	}
	oldSlice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "h-old",
			Namespace: "default",
			Labels:    map[string]string{discoveryv1.LabelServiceName: "h"},
			OwnerReferences: []metav1.OwnerReference{
				{Kind: "Service", Name: "h", UID: "uid-1"},
			},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{"10.0.0.99"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}},
		},
	}

	c.onServiceAdd(svc1)
	c.onServiceDelete(svc1)

	// Recreate before any slice for u1 is replayed. AddService
	// sees no entry, must still bind a UID guard.
	svc2 := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: "h", Namespace: "default", UID: "uid-2",
		},
		Spec: corev1.ServiceSpec{
			ClusterIP:  corev1.ClusterIPNone,
			ClusterIPs: []string{corev1.ClusterIPNone},
		},
	}
	c.onServiceAdd(svc2)

	// Now the late u1 slice arrives. It must be rejected, the
	// new Service is uid-2, this slice belongs to uid-1.
	c.onEndpointSliceAdd(oldSlice)

	c.slicesMu.Lock()
	entry := c.slicesByService["default/h"]
	c.slicesMu.Unlock()
	if entry == nil {
		t.Fatal("AddService for the recreated service must materialise a UID-bound entry")
	}
	if entry.svcUID != "uid-2" {
		t.Errorf("entry.svcUID: want uid-2, got %q", entry.svcUID)
	}
	if len(entry.slices) != 0 {
		t.Errorf("late u1 slice was accepted into entry: %+v", entry.slices)
	}

	rrs, _, ok := c.registry.ResolveQuery("h.default.svc.cluster.local.", dns.TypeA)
	if !ok {
		t.Fatal("recreated service should answer NOERROR/NODATA")
	}
	if len(rrs) != 0 {
		t.Errorf("recreated service must not surface stale endpoints, got %v", rrs)
	}
}

// TestStaleSliceFromStartupListEvicted covers the LIST-time race:
// the informer LIST returns Service-uid2 plus an old EndpointSlice
// whose ownerRef still points at uid1 (the previous incarnation
// that hasn't been GC'd yet). bindServiceUID must drop the stale
// slice when AddService stamps the entry with uid2, otherwise
// that slice's endpoints would get aggregated into the new
// service's answers.
func TestStaleSliceFromStartupListEvicted(t *testing.T) {
	c := newTestClient()
	ready := true

	staleSlice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "h-stale",
			Namespace: "default",
			Labels:    map[string]string{discoveryv1.LabelServiceName: "h"},
			OwnerReferences: []metav1.OwnerReference{
				{Kind: "Service", Name: "h", UID: "uid-1"},
			},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{"10.0.0.99"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}},
		},
	}
	freshSlice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "h-fresh",
			Namespace: "default",
			Labels:    map[string]string{discoveryv1.LabelServiceName: "h"},
			OwnerReferences: []metav1.OwnerReference{
				{Kind: "Service", Name: "h", UID: "uid-2"},
			},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{"10.0.0.1"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}},
		},
	}
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: "h", Namespace: "default", UID: "uid-2",
		},
		Spec: corev1.ServiceSpec{
			ClusterIP:  corev1.ClusterIPNone,
			ClusterIPs: []string{corev1.ClusterIPNone},
		},
	}

	// Endpoints-before-service ordering: both slices arrive
	// before any Service event.
	c.onEndpointSliceAdd(staleSlice)
	c.onEndpointSliceAdd(freshSlice)

	// AddService stamps uid-2; the slice tagged uid-1 must be
	// evicted, the slice tagged uid-2 kept.
	c.onServiceAdd(svc)

	rrs, _, ok := c.registry.ResolveQuery("h.default.svc.cluster.local.", dns.TypeA)
	if !ok || len(rrs) != 1 {
		t.Fatalf("expected 1 record, got ok=%v rrs=%v", ok, rrs)
	}
	if got := rrs[0].(*dns.A).A.String(); got != "10.0.0.1" {
		t.Errorf("expected 10.0.0.1 (fresh slice), got %s, stale slice survived UID check", got)
	}
}

// TestFormatReverseIP covers both v4 and v6 paths plus a non-IP input.
func TestFormatReverseIP(t *testing.T) {
	cases := []struct {
		ip   net.IP
		want string
	}{
		{net.ParseIP("10.96.0.1"), "1.0.96.10.in-addr.arpa."},
		{net.ParseIP("2001:db8::1"), "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."},
	}
	for _, c := range cases {
		if got := FormatReverseIP(c.ip); got != c.want {
			t.Errorf("FormatReverseIP(%s): want %s, got %s", c.ip, c.want, got)
		}
	}
	if got := FormatReverseIP(nil); got != "" {
		t.Errorf("FormatReverseIP(nil): want empty, got %q", got)
	}
}
