// Package kubernetes - Kubernetes API client
package kubernetes

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/semihalev/zlog/v2"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

// registryWriter is the subset of registry operations the
// informer callbacks use to populate a live cluster registry.
// Kubernetes.New passes in the registry that ServeDNS actually
// reads from — boring mode wires in the resolver's *Registry,
// killer mode wires in a *ShardedRegistry via shardedWriter.
// Previously the client kept its own private *Registry that
// nothing ever read, so a connected cluster answered with an
// empty dataset.
type registryWriter interface {
	AddService(*Service) error
	DeleteService(name, namespace string) error
	AddPod(*Pod) error
	DeletePod(name, namespace string) error
	SetEndpoints(service, namespace string, endpoints []Endpoint) error
}

// shardedWriter adapts *ShardedRegistry to registryWriter.
// ShardedRegistry's mutators don't return errors, so the adapter
// swallows nil and always reports success.
type shardedWriter struct {
	r *ShardedRegistry
}

func (w *shardedWriter) AddService(s *Service) error {
	w.r.AddService(s)
	return nil
}

func (w *shardedWriter) DeleteService(name, namespace string) error {
	w.r.DeleteService(name, namespace)
	return nil
}

func (w *shardedWriter) AddPod(p *Pod) error {
	w.r.AddPod(p)
	return nil
}

func (w *shardedWriter) DeletePod(name, namespace string) error {
	w.r.DeletePod(name, namespace)
	return nil
}

func (w *shardedWriter) SetEndpoints(service, namespace string, endpoints []Endpoint) error {
	w.r.SetEndpoints(service, namespace, endpoints)
	return nil
}

// Client connects to Kubernetes API.
type Client struct {
	clientset kubernetes.Interface
	registry  registryWriter
	stopCh    chan struct{}
	cancel    context.CancelFunc
	stopped   chan struct{}

	// synced flips to true once informers have populated the
	// registry. ServeDNS gates authoritative answers on this
	// so a still-warming-up or disconnected client doesn't
	// return NXDOMAIN against an empty registry for real
	// cluster names.
	synced atomic.Bool

	// slicesByService aggregates EndpointSlice contents per
	// service. A single service can have many slices; the
	// registry stores one endpoint list per service, so every
	// slice event must recompute the union.
	slicesMu        sync.Mutex
	slicesByService map[string]map[string][]Endpoint
}

// Synced reports whether the informer caches have populated
// the registry at least once.
func (c *Client) Synced() bool {
	return c.synced.Load()
}

// NewClient creates a new Kubernetes client. The registry
// parameter is the sink informer callbacks populate; passing the
// ServeDNS-facing registry wires live cluster state into query
// answers. A nil registry is rejected — nothing would be wired
// up, and silent no-ops hide config bugs.
func NewClient(kubeconfig string, registry registryWriter) (*Client, error) {
	if registry == nil {
		return nil, fmt.Errorf("kubernetes client: registry is nil")
	}
	// Build config - will use provided kubeconfig, in-cluster config, or ~/.kube/config
	cfg, err := buildConfig(kubeconfig)
	if err != nil {
		return nil, err
	}

	// Create clientset
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}

	// Test connection
	_, err = clientset.Discovery().ServerVersion()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to kubernetes: %w", err)
	}

	return &Client{
		clientset: clientset,
		registry:  registry,
		stopCh:    make(chan struct{}),
		stopped:   make(chan struct{}),
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

	// Add event handlers with error recovery
	serviceInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{ //nolint:gosec // G104 - event handler registration
		AddFunc:    c.safeServiceAdd,
		UpdateFunc: c.safeServiceUpdate,
		DeleteFunc: c.safeServiceDelete,
	})

	endpointSliceInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{ //nolint:gosec // G104 - event handler registration
		AddFunc:    c.safeEndpointSliceAdd,
		UpdateFunc: c.safeEndpointSliceUpdate,
		DeleteFunc: c.safeEndpointSliceDelete,
	})

	podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{ //nolint:gosec // G104 - event handler registration
		AddFunc:    c.safePodAdd,
		UpdateFunc: c.safePodUpdate,
		DeleteFunc: c.safePodDelete,
	})

	// Start informers
	go serviceInformer.Run(ctx.Done())
	go endpointSliceInformer.Run(ctx.Done())
	go podInformer.Run(ctx.Done())

	// Wait for caches to sync
	if !cache.WaitForCacheSync(ctx.Done(),
		serviceInformer.HasSynced,
		endpointSliceInformer.HasSynced,
		podInformer.HasSynced) {
		return fmt.Errorf("failed to sync caches")
	}

	c.synced.Store(true)
	zlog.Info("Kubernetes caches synced")

	// Wait for context cancellation or stop signal
	select {
	case <-ctx.Done():
	case <-c.stopCh:
	}

	// Cancel context to stop informers
	if c.cancel != nil {
		c.cancel()
	}

	return nil
}

// Stop stops the client and waits for cleanup
func (c *Client) Stop() {
	// Signal stop
	select {
	case <-c.stopCh:
		// Already stopped
		return
	default:
		close(c.stopCh)
	}

	// Cancel context if available
	if c.cancel != nil {
		c.cancel()
	}

	// Wait for Run to complete
	select {
	case <-c.stopped:
	case <-time.After(ClientStopTimeout):
		// Timeout after ClientStopTimeout
		zlog.Warn("Client stop timeout after", zlog.String("timeout", ClientStopTimeout.String()))
	}
}

// Safe wrappers for event handlers
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

// Service handlers
func (c *Client) onServiceAdd(obj any) {
	svc, ok := obj.(*corev1.Service)
	if !ok {
		zlog.Error("Invalid service object type",
			zlog.String("type", fmt.Sprintf("%T", obj)))
		return
	}
	service := c.convertService(svc)
	if err := c.registry.AddService(service); err != nil {
		zlog.Error("Failed to add service to registry",
			zlog.String("service", svc.Name),
			zlog.String("namespace", svc.Namespace),
			zlog.String("error", err.Error()))
	}
}

func (c *Client) onServiceUpdate(oldObj, newObj any) {
	svc, ok := newObj.(*corev1.Service)
	if !ok {
		zlog.Error("Invalid service object type in update",
			zlog.String("type", fmt.Sprintf("%T", newObj)))
		return
	}
	service := c.convertService(svc)
	if err := c.registry.AddService(service); err != nil {
		zlog.Error("Failed to update service in registry",
			zlog.String("service", svc.Name),
			zlog.String("namespace", svc.Namespace),
			zlog.String("error", err.Error()))
	}
}

func (c *Client) onServiceDelete(obj any) {
	svc, ok := obj.(*corev1.Service)
	if !ok {
		// DeleteFunc can deliver a tombstone when the final
		// object was missed by the informer — unwrap it so the
		// registry still sees the delete instead of keeping a
		// stale DNS record.
		if tombstone, tok := obj.(cache.DeletedFinalStateUnknown); tok {
			svc, ok = tombstone.Obj.(*corev1.Service)
		}
		if !ok {
			zlog.Error("Invalid service object type in delete",
				zlog.String("type", fmt.Sprintf("%T", obj)))
			return
		}
	}
	if err := c.registry.DeleteService(svc.Name, svc.Namespace); err != nil {
		zlog.Error("Failed to delete service from registry",
			zlog.String("service", svc.Name),
			zlog.String("namespace", svc.Namespace),
			zlog.String("error", err.Error()))
	}
}

// Safe wrappers for EndpointSlice handlers
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

// EndpointSlice handlers. A Kubernetes service can back its
// endpoints with many slices; every slice event must recompute
// the union across all slices for that service, otherwise
// slice-2's add would erase slice-1's endpoints and a delete
// would wipe the whole service.

// applyEndpointSlice updates the cached slice contents for a
// service and writes the aggregated endpoint set to the registry.
// Passing deleted=true removes the slice's contribution. The
// aggregation uses slice.Name as identity so repeated
// add/update events for the same slice replace — not append —
// that slice's endpoints.
func (c *Client) applyEndpointSlice(eps *discoveryv1.EndpointSlice, serviceName string, deleted bool) error {
	key := eps.Namespace + "/" + serviceName

	c.slicesMu.Lock()
	if c.slicesByService == nil {
		c.slicesByService = make(map[string]map[string][]Endpoint)
	}
	slices, ok := c.slicesByService[key]
	if !ok {
		if deleted {
			c.slicesMu.Unlock()
			return nil
		}
		slices = make(map[string][]Endpoint)
		c.slicesByService[key] = slices
	}
	if deleted {
		delete(slices, eps.Name)
	} else {
		slices[eps.Name] = c.convertEndpointSlice(eps)
	}

	var agg []Endpoint
	for _, s := range slices {
		agg = append(agg, s...)
	}
	if len(slices) == 0 {
		delete(c.slicesByService, key)
	}
	c.slicesMu.Unlock()

	return c.registry.SetEndpoints(serviceName, eps.Namespace, agg)
}

func (c *Client) onEndpointSliceAdd(obj any) {
	eps, ok := obj.(*discoveryv1.EndpointSlice)
	if !ok {
		zlog.Error("Invalid endpoint slice object type",
			zlog.String("type", fmt.Sprintf("%T", obj)))
		return
	}
	serviceName := eps.Labels["kubernetes.io/service-name"]
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
	serviceName := eps.Labels["kubernetes.io/service-name"]
	if serviceName == "" {
		return
	}
	if err := c.applyEndpointSlice(eps, serviceName, false); err != nil {
		zlog.Error("Failed to update endpoints in registry",
			zlog.String("service", serviceName),
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
	serviceName := eps.Labels["kubernetes.io/service-name"]
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

// Safe wrappers for Pod handlers
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

// Pod handlers
func (c *Client) onPodAdd(obj any) {
	p, ok := obj.(*corev1.Pod)
	if !ok {
		zlog.Error("Invalid pod object type",
			zlog.String("type", fmt.Sprintf("%T", obj)))
		return
	}
	pod := c.convertPod(p)
	if pod != nil {
		if err := c.registry.AddPod(pod); err != nil {
			zlog.Error("Failed to add pod to registry",
				zlog.String("pod", p.Name),
				zlog.String("namespace", p.Namespace),
				zlog.String("error", err.Error()))
		}
	}
}

func (c *Client) onPodUpdate(oldObj, newObj any) {
	p, ok := newObj.(*corev1.Pod)
	if !ok {
		zlog.Error("Invalid pod object type in update",
			zlog.String("type", fmt.Sprintf("%T", newObj)))
		return
	}

	// Both registries index pods by IP. If the pod moved to a
	// new address, AddPod on its own would write the new IP and
	// leave the old IP still pointing at this pod, so reverse
	// and pod-IP queries kept answering for the old IP. Remove
	// the prior indexes before inserting the new state.
	if err := c.registry.DeletePod(p.Name, p.Namespace); err != nil {
		zlog.Debug("Failed to clear prior pod indexes on update",
			zlog.String("pod", p.Name),
			zlog.String("namespace", p.Namespace),
			zlog.String("error", err.Error()))
	}

	pod := c.convertPod(p)
	if pod != nil {
		if err := c.registry.AddPod(pod); err != nil {
			zlog.Error("Failed to update pod in registry",
				zlog.String("pod", p.Name),
				zlog.String("namespace", p.Namespace),
				zlog.String("error", err.Error()))
		}
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
	if err := c.registry.DeletePod(p.Name, p.Namespace); err != nil {
		zlog.Error("Failed to delete pod from registry",
			zlog.String("pod", p.Name),
			zlog.String("namespace", p.Namespace),
			zlog.String("error", err.Error()))
	}
}

// Converters

func (c *Client) convertService(svc *corev1.Service) *Service {
	service := &Service{
		Name:      svc.Name,
		Namespace: svc.Namespace,
		Type:      string(svc.Spec.Type),
	}

	// Handle ClusterIPs. Read the plural field so dual-stack
	// services contribute both IPv4 and IPv6 ClusterIPs; fall back
	// to the singular field for older API objects. Previously this
	// only read ClusterIP, hardcoded IPv4, and called ip.To4 — so
	// IPv6-primary services stored nil and dual-stack secondary
	// addresses were silently dropped.
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

	// Handle ExternalName
	if svc.Spec.Type == corev1.ServiceTypeExternalName {
		service.ExternalName = svc.Spec.ExternalName
	}

	// Convert ports
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

		// discovery/v1 documents Ready==nil as "ready/true" —
		// controllers and custom producers often omit the
		// field. Treating nil as not-ready filtered those
		// endpoints out of headless-service answers.
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

	// Collect all pod IPs (supports dual-stack)
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

// buildConfig builds kubernetes config
func buildConfig(kubeconfig string) (*rest.Config, error) {
	// Try in-cluster config first
	if config, err := rest.InClusterConfig(); err == nil {
		return config, nil
	}

	// Try kubeconfig file
	if kubeconfig == "" {
		if home := homedir.HomeDir(); home != "" {
			kubeconfig = filepath.Join(home, ".kube", "config")
		}
	}

	if kubeconfig != "" {
		if _, err := os.Stat(kubeconfig); err == nil {
			return clientcmd.BuildConfigFromFlags("", kubeconfig)
		}
	}

	// Try KUBECONFIG env
	if kc := os.Getenv("KUBECONFIG"); kc != "" {
		return clientcmd.BuildConfigFromFlags("", kc)
	}

	return nil, fmt.Errorf("no kubernetes config found")
}
