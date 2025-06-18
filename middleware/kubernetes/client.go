// Package kubernetes - Kubernetes API client
package kubernetes

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/semihalev/zlog"
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

// Client connects to Kubernetes API.
type Client struct {
	clientset kubernetes.Interface
	registry  *Registry
	stopCh    chan struct{}
	cancel    context.CancelFunc
	stopped   chan struct{}
}

// NewClient creates a new Kubernetes client.
func NewClient(kubeconfig string) (*Client, error) {
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
		registry:  NewRegistry(),
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

	// Add event handlers
	serviceInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.onServiceAdd,
		UpdateFunc: c.onServiceUpdate,
		DeleteFunc: c.onServiceDelete,
	})

	endpointSliceInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.onEndpointSliceAdd,
		UpdateFunc: c.onEndpointSliceUpdate,
		DeleteFunc: c.onEndpointSliceDelete,
	})

	podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.onPodAdd,
		UpdateFunc: c.onPodUpdate,
		DeleteFunc: c.onPodDelete,
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
	case <-time.After(5 * time.Second):
		// Timeout after 5 seconds
		zlog.Warn("Client stop timeout after 5 seconds")
	}
}

// Service handlers
func (c *Client) onServiceAdd(obj interface{}) {
	svc := obj.(*corev1.Service)
	service := c.convertService(svc)
	c.registry.AddService(service)
}

func (c *Client) onServiceUpdate(oldObj, newObj interface{}) {
	svc := newObj.(*corev1.Service)
	service := c.convertService(svc)
	c.registry.AddService(service)
}

func (c *Client) onServiceDelete(obj interface{}) {
	svc := obj.(*corev1.Service)
	c.registry.DeleteService(svc.Name, svc.Namespace)
}

// EndpointSlice handlers
// Note: A service can have multiple EndpointSlices, so we need to aggregate them
func (c *Client) onEndpointSliceAdd(obj interface{}) {
	eps := obj.(*discoveryv1.EndpointSlice)
	serviceName := eps.Labels["kubernetes.io/service-name"]
	if serviceName != "" {
		// For simplicity, we're treating each slice independently
		// In production, you'd want to aggregate all slices for a service
		endpoints := c.convertEndpointSlice(eps)
		c.registry.SetEndpoints(serviceName, eps.Namespace, endpoints)
	}
}

func (c *Client) onEndpointSliceUpdate(oldObj, newObj interface{}) {
	eps := newObj.(*discoveryv1.EndpointSlice)
	serviceName := eps.Labels["kubernetes.io/service-name"]
	if serviceName != "" {
		endpoints := c.convertEndpointSlice(eps)
		c.registry.SetEndpoints(serviceName, eps.Namespace, endpoints)
	}
}

func (c *Client) onEndpointSliceDelete(obj interface{}) {
	eps := obj.(*discoveryv1.EndpointSlice)
	serviceName := eps.Labels["kubernetes.io/service-name"]
	if serviceName != "" {
		// TODO: This should aggregate remaining slices, not just clear
		c.registry.SetEndpoints(serviceName, eps.Namespace, nil)
	}
}

// Pod handlers
func (c *Client) onPodAdd(obj interface{}) {
	p := obj.(*corev1.Pod)
	pod := c.convertPod(p)
	if pod != nil {
		c.registry.AddPod(pod)
	}
}

func (c *Client) onPodUpdate(oldObj, newObj interface{}) {
	p := newObj.(*corev1.Pod)
	pod := c.convertPod(p)
	if pod != nil {
		c.registry.AddPod(pod)
	}
}

func (c *Client) onPodDelete(obj interface{}) {
	p := obj.(*corev1.Pod)
	c.registry.DeletePod(p.Name, p.Namespace)
}

// Converters

func (c *Client) convertService(svc *corev1.Service) *Service {
	service := &Service{
		Name:      svc.Name,
		Namespace: svc.Namespace,
		Type:      string(svc.Spec.Type),
	}

	// Handle ClusterIP
	if svc.Spec.ClusterIP != "" && svc.Spec.ClusterIP != "None" {
		if ip := net.ParseIP(svc.Spec.ClusterIP); ip != nil {
			service.ClusterIPs = append(service.ClusterIPs, ip.To4())
			if service.IPFamilies == nil {
				service.IPFamilies = []string{"IPv4"}
			}
		}
	}

	if svc.Spec.ClusterIP == "None" {
		service.Headless = true
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

		endpoint := Endpoint{
			Addresses: ep.Addresses,
			Ready:     ep.Conditions.Ready != nil && *ep.Conditions.Ready,
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
