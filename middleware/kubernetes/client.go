// Package kubernetes - Kubernetes API client
package kubernetes

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/semihalev/zlog/v2"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

// rebuildDebounce is the worker's wait window before flushing
// pending rebuilds so a burst of slice events for one service
// collapses into a single rebuild.
const rebuildDebounce = 50 * time.Millisecond

// Client connects to the Kubernetes API.
type Client struct {
	clientset kubernetes.Interface
	registry  *Registry
	stopCh    chan struct{}
	cancel    context.CancelFunc
	stopped   chan struct{}

	// synced flips to true once informers have populated the
	// registry. ServeDNS gates authoritative answers on this so
	// a warming-up or disconnected client doesn't return NXDOMAIN
	// for valid cluster names.
	synced atomic.Bool

	// slicesByService records UID-tracked slice contributions per
	// namespace/name. tombstones holds the UID of the most recently
	// deleted Service so a late slice event that arrives after the
	// delete is rejected before re-populating state.
	slicesMu        sync.Mutex
	slicesByService map[string]*serviceSlices
	tombstones      map[string]types.UID

	queue           *rebuildQueue
	rebuildDebounce time.Duration

	// rebuilds counts per-service rebuilds (ops signal).
	rebuilds atomic.Uint64
}

// serviceSlices tracks one service's slice events. svcUID is empty
// until the Service is observed (endpoints-before-service ordering).
// dirtySlices is the set forwarded to the registry on the next
// worker drain.
type serviceSlices struct {
	svcUID        types.UID
	slices        map[string][]Endpoint
	sliceOwnerUID map[string]types.UID
	dirtySlices   map[string]struct{}
}

// rebuildQueue is a set-typed work queue with a buffered (cap=1)
// notify channel. running gates scheduleRebuild; processingMu
// serialises drain dispatch so flushRebuilds can wait for an
// in-flight worker cycle to finish.
type rebuildQueue struct {
	mu           sync.Mutex
	pending      map[string]struct{}
	notify       chan struct{}
	running      atomic.Bool
	processingMu sync.Mutex
}

func newRebuildQueue() *rebuildQueue {
	return &rebuildQueue{
		pending: map[string]struct{}{},
		notify:  make(chan struct{}, 1),
	}
}

func (q *rebuildQueue) enqueue(key string) {
	q.mu.Lock()
	q.pending[key] = struct{}{}
	q.mu.Unlock()
	select {
	case q.notify <- struct{}{}:
	default:
	}
}

func (q *rebuildQueue) drain() []string {
	q.mu.Lock()
	keys := make([]string, 0, len(q.pending))
	for k := range q.pending {
		keys = append(keys, k)
		delete(q.pending, k)
	}
	q.mu.Unlock()
	return keys
}

// Synced reports whether the informer caches have populated the
// registry at least once.
func (c *Client) Synced() bool {
	return c.synced.Load()
}

// NewClient creates a new Kubernetes client wired to registry.
func NewClient(kubeconfig string, registry *Registry) (*Client, error) {
	if registry == nil {
		return nil, fmt.Errorf("kubernetes client: registry is nil")
	}
	cfg, err := buildConfig(kubeconfig)
	if err != nil {
		return nil, err
	}

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}

	_, err = clientset.Discovery().ServerVersion()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to kubernetes: %w", err)
	}

	return &Client{
		clientset: clientset,
		registry:  registry,
		stopCh:    make(chan struct{}),
		stopped:   make(chan struct{}),
		queue:     newRebuildQueue(),
	}, nil
}

// Run starts watching Kubernetes resources.
func (c *Client) Run(ctx context.Context) error {
	// Create cancellable context
	ctx, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	defer close(c.stopped)

	// Recover from any panics in informers
	defer func() {
		if r := recover(); r != nil {
			zlog.Error("Kubernetes client panicked",
				zlog.Any("panic", r),
				zlog.String("component", "informer"))
		}
	}()

	// Create informers
	serviceInformer := cache.NewSharedInformer(
		cache.NewListWatchFromClient(
			c.clientset.CoreV1().RESTClient(),
			"services",
			metav1.NamespaceAll,
			fields.Everything(),
		),
		&corev1.Service{},
		0,
	)

	endpointSliceInformer := cache.NewSharedInformer(
		cache.NewListWatchFromClient(
			c.clientset.DiscoveryV1().RESTClient(),
			"endpointslices",
			metav1.NamespaceAll,
			fields.Everything(),
		),
		&discoveryv1.EndpointSlice{},
		0,
	)

	podInformer := cache.NewSharedInformer(
		cache.NewListWatchFromClient(
			c.clientset.CoreV1().RESTClient(),
			"pods",
			metav1.NamespaceAll,
			fields.Everything(),
		),
		&corev1.Pod{},
		0,
	)

	// Capture the per-handler registrations so we can wait on each
	// HasSynced, informer-level HasSynced only reports the store
	// is populated, not that our AddFunc ran for every item.
	serviceReg, err := serviceInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.safeServiceAdd,
		UpdateFunc: c.safeServiceUpdate,
		DeleteFunc: c.safeServiceDelete,
	})
	if err != nil {
		return fmt.Errorf("register service handler: %w", err)
	}

	endpointSliceReg, err := endpointSliceInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.safeEndpointSliceAdd,
		UpdateFunc: c.safeEndpointSliceUpdate,
		DeleteFunc: c.safeEndpointSliceDelete,
	})
	if err != nil {
		return fmt.Errorf("register endpointslice handler: %w", err)
	}

	podReg, err := podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.safePodAdd,
		UpdateFunc: c.safePodUpdate,
		DeleteFunc: c.safePodDelete,
	})
	if err != nil {
		return fmt.Errorf("register pod handler: %w", err)
	}

	// Start the rebuild worker before informers so events arriving
	// during the initial sync are coalesced too. startRebuildWorker
	// flips running synchronously to avoid an inline-rebuild race.
	workerDone := c.startRebuildWorker(ctx)

	go serviceInformer.Run(ctx.Done())
	go endpointSliceInformer.Run(ctx.Done())
	go podInformer.Run(ctx.Done())

	if !cache.WaitForCacheSync(ctx.Done(),
		serviceInformer.HasSynced,
		endpointSliceInformer.HasSynced,
		podInformer.HasSynced,
		serviceReg.HasSynced,
		endpointSliceReg.HasSynced,
		podReg.HasSynced) {
		return fmt.Errorf("failed to sync caches")
	}

	// Drain queued rebuilds before publishing synced so ServeDNS
	// doesn't NODATA valid headless names during the debounce window.
	c.flushRebuilds()

	c.synced.Store(true)
	zlog.Info("Kubernetes caches synced")

	select {
	case <-ctx.Done():
	case <-c.stopCh:
	}

	if c.cancel != nil {
		c.cancel()
	}

	<-workerDone
	return nil
}

// Stop stops the client and waits for cleanup.
func (c *Client) Stop() {
	select {
	case <-c.stopCh:
		return
	default:
		close(c.stopCh)
	}

	if c.cancel != nil {
		c.cancel()
	}

	select {
	case <-c.stopped:
	case <-time.After(ClientStopTimeout):
		zlog.Warn("Client stop timeout after", zlog.String("timeout", ClientStopTimeout.String()))
	}
}

func (c *Client) safeServiceAdd(obj any) {
	defer func() {
		if r := recover(); r != nil {
			zlog.Error("Panic in service add handler",
				zlog.Any("panic", r),
				zlog.Any("object", obj))
		}
	}()
	c.onServiceAdd(obj)
}

func (c *Client) safeServiceUpdate(oldObj, newObj any) {
	defer func() {
		if r := recover(); r != nil {
			zlog.Error("Panic in service update handler",
				zlog.Any("panic", r),
				zlog.Any("object", newObj))
		}
	}()
	c.onServiceUpdate(oldObj, newObj)
}

func (c *Client) safeServiceDelete(obj any) {
	defer func() {
		if r := recover(); r != nil {
			zlog.Error("Panic in service delete handler",
				zlog.Any("panic", r),
				zlog.Any("object", obj))
		}
	}()
	c.onServiceDelete(obj)
}

func (c *Client) onServiceAdd(obj any) {
	svc, ok := obj.(*corev1.Service)
	if !ok {
		zlog.Error("Invalid service object type",
			zlog.String("type", fmt.Sprintf("%T", obj)))
		return
	}
	c.bindServiceUID(svc)
	c.markAllSlicesDirty(svc.Namespace, svc.Name)
	c.registry.AddService(c.convertService(svc))
	c.scheduleRebuildIfDirty(svc.Namespace, svc.Name)
}

func (c *Client) onServiceUpdate(oldObj, newObj any) {
	svc, ok := newObj.(*corev1.Service)
	if !ok {
		zlog.Error("Invalid service object type in update",
			zlog.String("type", fmt.Sprintf("%T", newObj)))
		return
	}
	c.bindServiceUID(svc)
	c.markAllSlicesDirty(svc.Namespace, svc.Name)
	c.registry.AddService(c.convertService(svc))
	c.scheduleRebuildIfDirty(svc.Namespace, svc.Name)
}

func (c *Client) scheduleRebuildIfDirty(namespace, serviceName string) {
	key := namespace + "/" + serviceName
	c.slicesMu.Lock()
	dirty := false
	if entry := c.slicesByService[key]; entry != nil && len(entry.dirtySlices) > 0 {
		dirty = true
	}
	c.slicesMu.Unlock()
	if dirty {
		c.scheduleRebuild(namespace, serviceName)
	}
}

func (c *Client) onServiceDelete(obj any) {
	svc, ok := obj.(*corev1.Service)
	if !ok {
		// Unwrap informer tombstones so a missed-final-state
		// delete still propagates.
		if tombstone, tok := obj.(cache.DeletedFinalStateUnknown); tok {
			svc, ok = tombstone.Obj.(*corev1.Service)
		}
		if !ok {
			zlog.Error("Invalid service object type in delete",
				zlog.String("type", fmt.Sprintf("%T", obj)))
			return
		}
	}

	// Set tombstone + clear slicesByService → flush queued rebuilds
	// → DeleteService. Reversing this lets a worker rebuild write
	// the registry AFTER DeleteService wiped it.
	key := svc.Namespace + "/" + svc.Name
	c.slicesMu.Lock()
	delete(c.slicesByService, key)
	if c.tombstones == nil {
		c.tombstones = map[string]types.UID{}
	}
	if svc.UID != "" {
		c.tombstones[key] = svc.UID
	} else {
		delete(c.tombstones, key)
	}
	c.slicesMu.Unlock()

	c.flushRebuilds()
	c.registry.DeleteService(svc.Name, svc.Namespace)
}

// bindServiceUID stamps svc.UID onto its slicesByService entry,
// clearing any prior tombstone. Always materialises an entry so
// the UID guard rejects late slice events from a previous
// incarnation, without a placeholder, a delete-then-recreate
// path would lose the guard and accept a stale slice. Slices
// whose ownerRef disagrees with svc.UID are evicted.
func (c *Client) bindServiceUID(svc *corev1.Service) {
	if svc.UID == "" {
		return
	}
	key := svc.Namespace + "/" + svc.Name
	c.slicesMu.Lock()
	delete(c.tombstones, key)

	if c.slicesByService == nil {
		c.slicesByService = map[string]*serviceSlices{}
	}

	dropped := false
	entry := c.slicesByService[key]
	switch {
	case entry == nil:
		c.slicesByService[key] = &serviceSlices{
			svcUID:        svc.UID,
			slices:        map[string][]Endpoint{},
			sliceOwnerUID: map[string]types.UID{},
		}
	case entry.svcUID != "" && entry.svcUID != svc.UID:
		c.slicesByService[key] = &serviceSlices{
			svcUID:        svc.UID,
			slices:        map[string][]Endpoint{},
			sliceOwnerUID: map[string]types.UID{},
		}
		dropped = true
	default:
		entry.svcUID = svc.UID
		for sliceName, ownerUID := range entry.sliceOwnerUID {
			if ownerUID != "" && ownerUID != svc.UID {
				delete(entry.slices, sliceName)
				delete(entry.sliceOwnerUID, sliceName)
				dropped = true
			}
		}
	}
	c.slicesMu.Unlock()

	if dropped {
		c.scheduleRebuild(svc.Namespace, svc.Name)
	}
}

// markAllSlicesDirty marks every tracked slice dirty so the next
// worker drain re-pushes them through registry.ApplyEndpointSlice.
// This is what replaces the synthetic-seed contribution (placed by
// the AddService rebuild path) with real per-slice state in one
// drain, instead of losing other slices on the first non-synthetic
// Apply.
func (c *Client) markAllSlicesDirty(namespace, serviceName string) {
	key := namespace + "/" + serviceName
	c.slicesMu.Lock()
	defer c.slicesMu.Unlock()
	entry := c.slicesByService[key]
	if entry == nil || len(entry.slices) == 0 {
		return
	}
	if entry.dirtySlices == nil {
		entry.dirtySlices = map[string]struct{}{}
	}
	for sliceName := range entry.slices {
		entry.dirtySlices[sliceName] = struct{}{}
	}
}

func (c *Client) safeEndpointSliceAdd(obj any) {
	defer func() {
		if r := recover(); r != nil {
			zlog.Error("Panic in endpoint slice add handler",
				zlog.Any("panic", r),
				zlog.Any("object", obj))
		}
	}()
	c.onEndpointSliceAdd(obj)
}

func (c *Client) safeEndpointSliceUpdate(oldObj, newObj any) {
	defer func() {
		if r := recover(); r != nil {
			zlog.Error("Panic in endpoint slice update handler",
				zlog.Any("panic", r),
				zlog.Any("object", newObj))
		}
	}()
	c.onEndpointSliceUpdate(oldObj, newObj)
}

func (c *Client) safeEndpointSliceDelete(obj any) {
	defer func() {
		if r := recover(); r != nil {
			zlog.Error("Panic in endpoint slice delete handler",
				zlog.Any("panic", r),
				zlog.Any("object", obj))
		}
	}()
	c.onEndpointSliceDelete(obj)
}

// applyEndpointSlice records sliceName's contribution and schedules
// a rebuild. Late events for a deleted Service (tombstone match) or
// a Service whose UID disagrees with the slice's owner are dropped.
func (c *Client) applyEndpointSlice(eps *discoveryv1.EndpointSlice, serviceName string, deleted bool) error {
	key := eps.Namespace + "/" + serviceName
	ownerUID := sliceOwnerUID(eps, serviceName)

	c.slicesMu.Lock()
	if ownerUID != "" {
		if tomb, ok := c.tombstones[key]; ok && tomb == ownerUID {
			c.slicesMu.Unlock()
			return nil
		}
	}

	if c.slicesByService == nil {
		c.slicesByService = make(map[string]*serviceSlices)
	}
	entry, ok := c.slicesByService[key]
	if !ok {
		if deleted {
			c.slicesMu.Unlock()
			return nil
		}
		entry = &serviceSlices{
			slices:        map[string][]Endpoint{},
			sliceOwnerUID: map[string]types.UID{},
			dirtySlices:   map[string]struct{}{},
		}
		c.slicesByService[key] = entry
	}
	if entry.svcUID != "" && ownerUID != "" && ownerUID != entry.svcUID {
		c.slicesMu.Unlock()
		return nil
	}
	if deleted {
		if _, present := entry.slices[eps.Name]; !present {
			c.slicesMu.Unlock()
			return nil
		}
		delete(entry.slices, eps.Name)
		delete(entry.sliceOwnerUID, eps.Name)
		entry.markDirty(eps.Name)
	} else {
		converted := c.convertEndpointSlice(eps)
		if existing, present := entry.slices[eps.Name]; present && endpointsEqual(existing, converted) {
			if ownerUID != "" {
				entry.sliceOwnerUID[eps.Name] = ownerUID
			}
			c.slicesMu.Unlock()
			return nil
		}
		entry.slices[eps.Name] = converted
		if ownerUID != "" {
			entry.sliceOwnerUID[eps.Name] = ownerUID
		} else {
			delete(entry.sliceOwnerUID, eps.Name)
		}
		entry.markDirty(eps.Name)
	}
	// Entry deletion is deferred to rebuildService, dropping it
	// here would lose the dirtySlices set.
	c.slicesMu.Unlock()

	c.scheduleRebuild(eps.Namespace, serviceName)
	return nil
}

// endpointsEqual is the no-op guard for resourceVersion-only
// EndpointSlice update events.
func endpointsEqual(a, b []Endpoint) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Hostname != b[i].Hostname || a[i].Ready != b[i].Ready {
			return false
		}
		if len(a[i].Addresses) != len(b[i].Addresses) {
			return false
		}
		for j := range a[i].Addresses {
			if a[i].Addresses[j] != b[i].Addresses[j] {
				return false
			}
		}
		ar, br := a[i].TargetRef, b[i].TargetRef
		if (ar == nil) != (br == nil) {
			return false
		}
		if ar != nil && (ar.Kind != br.Kind || ar.Name != br.Name || ar.Namespace != br.Namespace) {
			return false
		}
	}
	return true
}

// sliceOwnerUID returns the Service UID from OwnerReferences, or
// "" if absent (test fixtures, older objects).
func sliceOwnerUID(eps *discoveryv1.EndpointSlice, serviceName string) types.UID {
	for _, ref := range eps.OwnerReferences {
		if ref.Kind == "Service" && ref.Name == serviceName {
			return ref.UID
		}
	}
	return ""
}

// scheduleRebuild routes through the worker queue when running,
// else rebuilds inline (test path).
func (c *Client) scheduleRebuild(namespace, serviceName string) {
	if c.queue != nil && c.queue.running.Load() {
		c.queue.enqueue(namespace + "/" + serviceName)
		return
	}
	c.rebuildService(namespace, serviceName)
}

func (e *serviceSlices) markDirty(sliceName string) {
	if e.dirtySlices == nil {
		e.dirtySlices = map[string]struct{}{}
	}
	e.dirtySlices[sliceName] = struct{}{}
}

// rebuildService publishes recorded changes to the registry.
// Headless services forward each dirty slice through the per-slice
// API (O(slice size) instead of aggregation); non-headless services
// keep the legacy aggregate-and-SetEndpoints path since their DNS
// records come from svc.ClusterIPs, not endpoints.
func (c *Client) rebuildService(namespace, serviceName string) {
	defer c.rebuilds.Add(1)

	key := namespace + "/" + serviceName
	svc := c.registry.GetService(serviceName, namespace)
	headless := svc != nil && svc.Headless

	if !headless {
		c.slicesMu.Lock()
		var agg []Endpoint
		if entry := c.slicesByService[key]; entry != nil && len(entry.slices) > 0 {
			total := 0
			for _, s := range entry.slices {
				total += len(s)
			}
			agg = make([]Endpoint, 0, total)
			for _, s := range entry.slices {
				agg = append(agg, s...)
			}
			entry.dirtySlices = nil
		}
		c.slicesMu.Unlock()
		c.registry.SetEndpoints(serviceName, namespace, agg)
		return
	}

	// Snapshot dirty slices and forward individually. Slices missing
	// from entry.slices were deleted (registry takes Remove). A nil
	// dirtySlices set means no per-slice tracking yet, forward
	// every current slice; the registry deduplicates via its
	// own equality guard.
	type sliceUpdate struct {
		name    string
		eps     []Endpoint
		removed bool
	}
	var updates []sliceUpdate
	c.slicesMu.Lock()
	if entry := c.slicesByService[key]; entry != nil {
		if entry.dirtySlices == nil {
			for sliceName, eps := range entry.slices {
				updates = append(updates, sliceUpdate{name: sliceName, eps: eps})
			}
		} else {
			for sliceName := range entry.dirtySlices {
				eps, present := entry.slices[sliceName]
				updates = append(updates, sliceUpdate{
					name:    sliceName,
					eps:     eps,
					removed: !present,
				})
			}
		}
		entry.dirtySlices = map[string]struct{}{}
		if len(entry.slices) == 0 && entry.svcUID == "" {
			delete(c.slicesByService, key)
		}
	}
	c.slicesMu.Unlock()

	for _, u := range updates {
		if u.removed {
			c.registry.RemoveEndpointSlice(serviceName, namespace, u.name)
		} else {
			c.registry.ApplyEndpointSlice(serviceName, namespace, u.name, u.eps)
		}
	}
	c.registry.MaterialiseHeadless(serviceName, namespace)
}

// Rebuilds returns the total number of per-service rebuilds.
func (c *Client) Rebuilds() uint64 {
	return c.rebuilds.Load()
}

// startRebuildWorker flips running synchronously before launching
// the goroutine so the first informer callback never falls back to
// the inline-rebuild path.
func (c *Client) startRebuildWorker(ctx context.Context) <-chan struct{} {
	if c.queue == nil {
		c.queue = newRebuildQueue()
	}
	c.queue.running.Store(true)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer c.queue.running.Store(false)
		c.runRebuildWorker(ctx)
	}()
	return done
}

func (c *Client) runRebuildWorker(ctx context.Context) {
	debounce := c.rebuildDebounce
	if debounce <= 0 {
		debounce = rebuildDebounce
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.queue.notify:
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(debounce):
		}

		c.processPending()
	}
}

// processPending holds processingMu for the entire drain so
// flushRebuilds can wait for an in-flight cycle to finish.
func (c *Client) processPending() {
	c.queue.processingMu.Lock()
	defer c.queue.processingMu.Unlock()
	for _, key := range c.queue.drain() {
		ns, name, ok := strings.Cut(key, "/")
		if !ok {
			continue
		}
		c.rebuildService(ns, name)
	}
}

// flushRebuilds drains the queue and waits for any concurrent
// worker dispatch to finish. Used after WaitForCacheSync so
// synced=true reflects a fully-rebuilt registry.
func (c *Client) flushRebuilds() {
	if c.queue == nil {
		return
	}
	c.processPending()
}

func (c *Client) onEndpointSliceAdd(obj any) {
	eps, ok := obj.(*discoveryv1.EndpointSlice)
	if !ok {
		zlog.Error("Invalid endpoint slice object type",
			zlog.String("type", fmt.Sprintf("%T", obj)))
		return
	}
	serviceName := eps.Labels[discoveryv1.LabelServiceName]
	if serviceName == "" {
		return
	}
	if err := c.applyEndpointSlice(eps, serviceName, false); err != nil {
		zlog.Error("Failed to add endpoints to registry",
			zlog.String("service", serviceName),
			zlog.String("namespace", eps.Namespace),
			zlog.String("error", err.Error()))
	}
}

func (c *Client) onEndpointSliceUpdate(oldObj, newObj any) {
	eps, ok := newObj.(*discoveryv1.EndpointSlice)
	if !ok {
		zlog.Error("Invalid endpoint slice object type in update",
			zlog.String("type", fmt.Sprintf("%T", newObj)))
		return
	}
	newServiceName := eps.Labels[discoveryv1.LabelServiceName]

	// On a service-name relabel (or label removal), retract the
	// slice's contribution from the previous service so it doesn't
	// keep stale endpoints.
	if oldEps, ok := oldObj.(*discoveryv1.EndpointSlice); ok {
		oldServiceName := oldEps.Labels[discoveryv1.LabelServiceName]
		if oldServiceName != "" && oldServiceName != newServiceName {
			if err := c.applyEndpointSlice(oldEps, oldServiceName, true); err != nil {
				zlog.Error("Failed to retract endpoints after service-name relabel",
					zlog.String("old_service", oldServiceName),
					zlog.String("new_service", newServiceName),
					zlog.String("namespace", oldEps.Namespace),
					zlog.String("error", err.Error()))
			}
		}
	}

	if newServiceName == "" {
		return
	}
	if err := c.applyEndpointSlice(eps, newServiceName, false); err != nil {
		zlog.Error("Failed to update endpoints in registry",
			zlog.String("service", newServiceName),
			zlog.String("namespace", eps.Namespace),
			zlog.String("error", err.Error()))
	}
}

func (c *Client) onEndpointSliceDelete(obj any) {
	eps, ok := obj.(*discoveryv1.EndpointSlice)
	if !ok {
		if tombstone, tok := obj.(cache.DeletedFinalStateUnknown); tok {
			eps, ok = tombstone.Obj.(*discoveryv1.EndpointSlice)
		}
		if !ok {
			zlog.Error("Invalid endpoint slice object type in delete",
				zlog.String("type", fmt.Sprintf("%T", obj)))
			return
		}
	}
	serviceName := eps.Labels[discoveryv1.LabelServiceName]
	if serviceName == "" {
		return
	}
	if err := c.applyEndpointSlice(eps, serviceName, true); err != nil {
		zlog.Error("Failed to delete endpoints from registry",
			zlog.String("service", serviceName),
			zlog.String("namespace", eps.Namespace),
			zlog.String("error", err.Error()))
	}
}

func (c *Client) safePodAdd(obj any) {
	defer func() {
		if r := recover(); r != nil {
			zlog.Error("Panic in pod add handler",
				zlog.Any("panic", r),
				zlog.Any("object", obj))
		}
	}()
	c.onPodAdd(obj)
}

func (c *Client) safePodUpdate(oldObj, newObj any) {
	defer func() {
		if r := recover(); r != nil {
			zlog.Error("Panic in pod update handler",
				zlog.Any("panic", r),
				zlog.Any("object", newObj))
		}
	}()
	c.onPodUpdate(oldObj, newObj)
}

func (c *Client) safePodDelete(obj any) {
	defer func() {
		if r := recover(); r != nil {
			zlog.Error("Panic in pod delete handler",
				zlog.Any("panic", r),
				zlog.Any("object", obj))
		}
	}()
	c.onPodDelete(obj)
}

func (c *Client) onPodAdd(obj any) {
	p, ok := obj.(*corev1.Pod)
	if !ok {
		zlog.Error("Invalid pod object type",
			zlog.String("type", fmt.Sprintf("%T", obj)))
		return
	}
	if pod := c.convertPod(p); pod != nil {
		c.registry.AddPod(pod)
	}
}

func (c *Client) onPodUpdate(oldObj, newObj any) {
	p, ok := newObj.(*corev1.Pod)
	if !ok {
		zlog.Error("Invalid pod object type in update",
			zlog.String("type", fmt.Sprintf("%T", newObj)))
		return
	}

	// Pod IPs may have changed; DeletePod first so the old IP's
	// index doesn't keep pointing at this pod.
	c.registry.DeletePod(p.Name, p.Namespace)

	if pod := c.convertPod(p); pod != nil {
		c.registry.AddPod(pod)
	}
}

func (c *Client) onPodDelete(obj any) {
	p, ok := obj.(*corev1.Pod)
	if !ok {
		if tombstone, tok := obj.(cache.DeletedFinalStateUnknown); tok {
			p, ok = tombstone.Obj.(*corev1.Pod)
		}
		if !ok {
			zlog.Error("Invalid pod object type in delete",
				zlog.String("type", fmt.Sprintf("%T", obj)))
			return
		}
	}
	c.registry.DeletePod(p.Name, p.Namespace)
}

func (c *Client) convertService(svc *corev1.Service) *Service {
	service := &Service{
		Name:      svc.Name,
		Namespace: svc.Namespace,
		Type:      string(svc.Spec.Type),
	}

	if svc.Spec.ClusterIP == "None" {
		service.Headless = true
	} else {
		clusterIPs := svc.Spec.ClusterIPs
		if len(clusterIPs) == 0 && svc.Spec.ClusterIP != "" {
			clusterIPs = []string{svc.Spec.ClusterIP}
		}
		for _, s := range clusterIPs {
			if s == "" || s == "None" {
				continue
			}
			ip := net.ParseIP(s)
			if ip == nil {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				service.ClusterIPs = append(service.ClusterIPs, ip4)
				service.IPFamilies = append(service.IPFamilies, "IPv4")
				continue
			}
			if ip6 := ip.To16(); ip6 != nil {
				service.ClusterIPs = append(service.ClusterIPs, ip6)
				service.IPFamilies = append(service.IPFamilies, "IPv6")
			}
		}
	}

	if svc.Spec.Type == corev1.ServiceTypeExternalName {
		service.ExternalName = svc.Spec.ExternalName
	}

	for _, p := range svc.Spec.Ports {
		service.Ports = append(service.Ports, Port{
			Name:     p.Name,
			Port:     int(p.Port),
			Protocol: string(p.Protocol),
		})
	}

	return service
}

func (c *Client) convertEndpointSlice(eps *discoveryv1.EndpointSlice) []Endpoint {
	var endpoints []Endpoint

	for _, ep := range eps.Endpoints {
		if len(ep.Addresses) == 0 {
			continue
		}

		// discovery/v1 documents Ready==nil as ready=true.
		endpoint := Endpoint{
			Addresses: ep.Addresses,
			Ready:     ep.Conditions.Ready == nil || *ep.Conditions.Ready,
		}

		if ep.Hostname != nil {
			endpoint.Hostname = *ep.Hostname
		}

		if ep.TargetRef != nil {
			endpoint.TargetRef = &ObjectRef{
				Kind:      ep.TargetRef.Kind,
				Name:      ep.TargetRef.Name,
				Namespace: ep.TargetRef.Namespace,
			}
		}

		endpoints = append(endpoints, endpoint)
	}

	return endpoints
}

func (c *Client) convertPod(p *corev1.Pod) *Pod {
	if p.Status.PodIP == "" {
		return nil
	}

	ips := []string{p.Status.PodIP}
	for _, podIP := range p.Status.PodIPs {
		if podIP.IP != "" && podIP.IP != p.Status.PodIP {
			ips = append(ips, podIP.IP)
		}
	}

	pod := &Pod{
		Name:      p.Name,
		Namespace: p.Namespace,
		IPs:       ips,
	}
	if p.Spec.Hostname != "" {
		pod.Hostname = p.Spec.Hostname
	}
	if p.Spec.Subdomain != "" {
		pod.Subdomain = p.Spec.Subdomain
	}
	return pod
}

// buildConfig resolves the Kubernetes REST config. Precedence:
// explicit kubeconfig path → in-cluster → KUBECONFIG env (multi-file)
// / ~/.kube/config via clientcmd's default loading rules. An explicit
// path must beat in-cluster so an operator-supplied kubeconfig isn't
// silently overridden by a service-account mount.
func buildConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		if _, err := os.Stat(kubeconfig); err != nil {
			return nil, fmt.Errorf("kubeconfig %q: %w", kubeconfig, err)
		}
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}

	if config, err := rest.InClusterConfig(); err == nil {
		return config, nil
	}

	// clientcmd's default rules merge multi-path KUBECONFIG entries
	// correctly; passing KUBECONFIG to BuildConfigFromFlags would
	// treat the colon-separated list as one literal path.
	loader := clientcmd.NewDefaultClientConfigLoadingRules()
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loader, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("no kubernetes config found: %w", err)
	}
	return cfg, nil
}
