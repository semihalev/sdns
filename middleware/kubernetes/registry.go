// Package kubernetes - Service registry
package kubernetes

import (
	"fmt"
	"net"
	"sync"
)

// Registry stores Kubernetes resources
type Registry struct {
	services  map[string]*Service
	endpoints map[string][]Endpoint
	pods      map[string]*Pod
	podsByIP  map[string]*Pod

	mu sync.RWMutex
}

// NewRegistry creates a new registry
func NewRegistry() *Registry {
	return &Registry{
		services:  make(map[string]*Service),
		endpoints: make(map[string][]Endpoint),
		pods:      make(map[string]*Pod),
		podsByIP:  make(map[string]*Pod),
	}
}

// AddService adds or updates a service
func (r *Registry) AddService(svc *Service) error {
	if svc == nil {
		return fmt.Errorf("service is nil")
	}
	if svc.Name == "" || svc.Namespace == "" {
		return fmt.Errorf("service name or namespace is empty")
	}
	
	r.mu.Lock()
	defer r.mu.Unlock()

	key := svc.Namespace + "/" + svc.Name
	r.services[key] = svc
	return nil
}

// GetService retrieves a service
func (r *Registry) GetService(name, namespace string) *Service {
	r.mu.RLock()
	defer r.mu.RUnlock()

	key := namespace + "/" + name
	return r.services[key]
}

// GetServiceByIP finds service by ClusterIP (supports dual-stack)
func (r *Registry) GetServiceByIP(ip []byte) *Service {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ipToFind := net.IP(ip)

	for _, svc := range r.services {
		// Check all ClusterIPs
		for _, clusterIP := range svc.ClusterIPs {
			if net.IP(clusterIP).Equal(ipToFind) {
				return svc
			}
		}
	}

	return nil
}

// SetEndpoints sets endpoints for a service
func (r *Registry) SetEndpoints(service, namespace string, endpoints []Endpoint) error {
	if service == "" || namespace == "" {
		return fmt.Errorf("service name or namespace is empty")
	}
	
	r.mu.Lock()
	defer r.mu.Unlock()

	key := namespace + "/" + service
	if endpoints == nil {
		delete(r.endpoints, key)
	} else {
		r.endpoints[key] = endpoints
	}
	return nil
}

// GetEndpoints retrieves endpoints for a service
func (r *Registry) GetEndpoints(service, namespace string) []Endpoint {
	r.mu.RLock()
	defer r.mu.RUnlock()

	key := namespace + "/" + service
	return r.endpoints[key]
}

// AddPod adds or updates a pod
func (r *Registry) AddPod(pod *Pod) error {
	if pod == nil {
		return fmt.Errorf("pod is nil")
	}
	if pod.Name == "" || pod.Namespace == "" {
		return fmt.Errorf("pod name or namespace is empty")
	}
	if len(pod.IPs) == 0 {
		return fmt.Errorf("pod has no IPs")
	}
	
	r.mu.Lock()
	defer r.mu.Unlock()

	key := pod.Namespace + "/" + pod.Name
	r.pods[key] = pod

	// Index all IPs
	for _, ip := range pod.IPs {
		if ip != "" {
			r.podsByIP[ip] = pod
		}
	}
	return nil
}

// GetPodByName retrieves a pod by name
func (r *Registry) GetPodByName(name, namespace string) *Pod {
	r.mu.RLock()
	defer r.mu.RUnlock()

	key := namespace + "/" + name
	return r.pods[key]
}

// GetPodByIP retrieves a pod by IP
func (r *Registry) GetPodByIP(ip string) *Pod {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.podsByIP[ip]
}

// DeleteService removes a service
func (r *Registry) DeleteService(name, namespace string) error {
	if name == "" || namespace == "" {
		return fmt.Errorf("service name or namespace is empty")
	}
	
	r.mu.Lock()
	defer r.mu.Unlock()

	key := namespace + "/" + name
	delete(r.services, key)
	delete(r.endpoints, key)
	return nil
}

// DeletePod removes a pod
func (r *Registry) DeletePod(name, namespace string) error {
	if name == "" || namespace == "" {
		return fmt.Errorf("pod name or namespace is empty")
	}
	
	r.mu.Lock()
	defer r.mu.Unlock()

	key := namespace + "/" + name
	pod := r.pods[key]
	if pod != nil {
		delete(r.pods, key)
		// Remove from all IP indexes
		for _, ip := range pod.IPs {
			if ip != "" {
				delete(r.podsByIP, ip)
			}
		}
	}
	return nil
}

// Stats returns registry statistics
// GetPods returns all pods in a namespace
func (r *Registry) GetPods(namespace string) []*Pod {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var pods []*Pod
	for _, pod := range r.pods {
		if pod.Namespace == namespace {
			pods = append(pods, pod)
		}
	}
	return pods
}

func (r *Registry) Stats() map[string]int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	endpointCount := 0
	for _, eps := range r.endpoints {
		endpointCount += len(eps)
	}

	return map[string]int{
		"services":  len(r.services),
		"endpoints": endpointCount,
		"pods":      len(r.pods),
	}
}
