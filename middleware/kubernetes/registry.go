package kubernetes

import (
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
	"github.com/semihalev/zlog/v2"
)

// Registry is a 256-way sharded store of services, pods, and
// endpoints with pre-built DNS answers per FQDN.
type Registry struct {
	serviceShards  [256]*serviceShard
	podShards      [256]*podShard
	endpointShards [256]*endpointShard
	podByName      [256]*podByNameShard
	serviceByIP    [256]*serviceByIPShard
	headlessShards [256]*headlessShard
	answerShards   [256]*answerShard

	queries uint64
	hits    uint64

	ttlService uint32
	ttlPod     uint32
	ttlSRV     uint32
	ttlPTR     uint32

	clusterDomain string
	svcSuffix     string
	podSuffix     string
}

type answerShard struct {
	mu      sync.RWMutex
	entries map[string]*answerSet
}

// answerSet holds the dns.RR slices for one FQDN. Empty (non-nil)
// slices mean NOERROR/NODATA; nil means fall through. fallback is
// returned for qtypes without a dedicated slot (ExternalName
// CNAME-for-any). srvExtra is the SRV Additional glue.
type answerSet struct {
	a        []dns.RR
	aaaa     []dns.RR
	cname    []dns.RR
	srv      []dns.RR
	ptr      []dns.RR
	fallback []dns.RR
	srvExtra []dns.RR
}

type serviceShard struct {
	mu       sync.RWMutex
	services map[string]*Service
}

type podShard struct {
	mu   sync.RWMutex
	pods map[string]*Pod
}

type endpointShard struct {
	mu        sync.RWMutex
	endpoints map[string][]Endpoint
}

type podByNameShard struct {
	mu   sync.RWMutex
	pods map[string]*Pod
}

type serviceByIPShard struct {
	mu       sync.RWMutex
	services map[string]*Service
}

type headlessShard struct {
	mu     sync.Mutex
	states map[string]*headlessSliceState
}

// headlessSliceState carries the incremental per-slice state for
// one headless service. RR pointers (aggA/aggAAAA/perTargetA/AAAA/
// srvByPort) are reused across rebuilds when their IP or target
// survives, keeping allocation cost O(delta).
type headlessSliceState struct {
	mu sync.Mutex

	contribs map[string][]Endpoint
	refs     map[string]map[string]int

	aggA    map[string]*dns.A
	aggAAAA map[string]*dns.AAAA

	perTargetA    map[string]map[string]*dns.A
	perTargetAAAA map[string]map[string]*dns.AAAA

	srvByPort map[string]map[string]*dns.SRV

	targetOrder []string

	svc       *Service
	fqdn      string
	ttlSvc    uint32
	ttlSRVval uint32

	pendingClears  map[string]struct{}
	dirtyTargets   map[string]struct{}
	aggregateDirty bool
	targetSetDirty bool
	portsHash      uint64
}

// NewRegistry creates an empty registry with all shards initialised.
func NewRegistry() *Registry {
	r := &Registry{
		ttlService: DefaultServiceTTL,
		ttlPod:     DefaultPodTTL,
		ttlSRV:     DefaultSRVTTL,
		ttlPTR:     DefaultPTRTTL,
	}
	r.SetClusterDomain("cluster.local")

	for i := 0; i < 256; i++ {
		r.serviceShards[i] = &serviceShard{services: make(map[string]*Service)}
		r.podShards[i] = &podShard{pods: make(map[string]*Pod)}
		r.endpointShards[i] = &endpointShard{endpoints: make(map[string][]Endpoint)}
		r.podByName[i] = &podByNameShard{pods: make(map[string]*Pod)}
		r.serviceByIP[i] = &serviceByIPShard{services: make(map[string]*Service)}
		r.headlessShards[i] = &headlessShard{states: make(map[string]*headlessSliceState)}
		r.answerShards[i] = &answerShard{entries: make(map[string]*answerSet)}
	}

	return r
}

// SetClusterDomain configures the cluster suffix used for suffix
// matching and PTR/SRV target construction. The input is lowercased
// and stripped of any trailing dot.
func (r *Registry) SetClusterDomain(domain string) {
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	if domain == "" {
		domain = "cluster.local"
	}
	r.clusterDomain = domain
	r.svcSuffix = ".svc." + domain + "."
	r.podSuffix = ".pod." + domain + "."
}

// SetTTLs sets custom TTL values; 0 keeps the default.
func (r *Registry) SetTTLs(service, pod, srv, ptr uint32) {
	if service > 0 {
		r.ttlService = service
	}
	if pod > 0 {
		r.ttlPod = pod
	}
	if srv > 0 {
		r.ttlSRV = srv
	}
	if ptr > 0 {
		r.ttlPTR = ptr
	}
}

// ResolveQuery resolves a DNS query against the registry. Returns
// ok=false for unknown names; ok=true with a nil/empty answer means
// authoritative NOERROR/NODATA. SRV queries return A/AAAA glue in
// extra.
func (r *Registry) ResolveQuery(qname string, qtype uint16) (answer, extra []dns.RR, ok bool) {
	atomic.AddUint64(&r.queries, 1)
	answer, extra, ok = r.cachedAnswer(qname, qtype)
	if ok {
		atomic.AddUint64(&r.hits, 1)
	}
	return answer, extra, ok
}

func (r *Registry) cachedAnswer(qname string, qtype uint16) (answer, extra []dns.RR, ok bool) {
	shard := r.getAnswerShard(qname)
	shard.mu.RLock()
	set := shard.entries[qname]
	shard.mu.RUnlock()
	if set == nil {
		return nil, nil, false
	}
	switch qtype {
	case dns.TypeA:
		if len(set.a) > 0 {
			return set.a, nil, true
		}
	case dns.TypeAAAA:
		if len(set.aaaa) > 0 {
			return set.aaaa, nil, true
		}
	case dns.TypeCNAME:
		if len(set.cname) > 0 {
			return set.cname, nil, true
		}
	case dns.TypeSRV:
		if len(set.srv) > 0 {
			return set.srv, set.srvExtra, true
		}
	case dns.TypePTR:
		if len(set.ptr) > 0 {
			return set.ptr, nil, true
		}
	case dns.TypeANY:
		return collectAny(set), nil, true
	}
	if len(set.fallback) > 0 {
		return set.fallback, nil, true
	}
	return nil, nil, true
}

func collectAny(set *answerSet) []dns.RR {
	n := len(set.a) + len(set.aaaa) + len(set.cname) + len(set.srv) + len(set.ptr)
	if n == 0 {
		return nil
	}
	out := make([]dns.RR, 0, n)
	out = append(out, set.a...)
	out = append(out, set.aaaa...)
	out = append(out, set.cname...)
	out = append(out, set.srv...)
	out = append(out, set.ptr...)
	return out
}

func (r *Registry) getAnswerShard(qname string) *answerShard {
	hash := uint32(0)
	for i := 0; i < len(qname); i++ {
		hash = hash*31 + uint32(qname[i])
	}
	return r.answerShards[hash%256]
}

// putAnswer stores set under qname; pass nil to clear.
func (r *Registry) putAnswer(qname string, set *answerSet) {
	shard := r.getAnswerShard(qname)
	shard.mu.Lock()
	if set == nil {
		delete(shard.entries, qname)
	} else {
		shard.entries[qname] = set
	}
	shard.mu.Unlock()
}

func (r *Registry) AddService(svc *Service) {
	if svc == nil {
		zlog.Error("Attempted to add nil service to registry")
		return
	}
	if svc.Name == "" || svc.Namespace == "" {
		zlog.Error("Attempted to add service with empty name or namespace",
			zlog.String("name", svc.Name),
			zlog.String("namespace", svc.Namespace))
		return
	}

	key := svc.Namespace + "/" + svc.Name
	shard := r.getServiceShard(key)
	shard.mu.Lock()
	prev := shard.services[key]
	shard.services[key] = svc
	shard.mu.Unlock()

	if prev != nil {
		r.removeServiceIPs(prev)
		r.uncacheServiceAnswers(prev)
		// Drop incremental state on headless→ClusterIP transitions
		// so stale anonymous-target entries don't outlive the mode.
		if prev.Headless && !svc.Headless {
			r.dropHeadlessState(prev)
		}
	}
	for _, ip := range svc.ClusterIPs {
		ipStr := net.IP(ip).String()
		if ipStr == "" || ipStr == "<nil>" {
			continue
		}
		ipShard := r.getServiceByIPShard(ipStr)
		ipShard.mu.Lock()
		ipShard.services[ipStr] = svc
		ipShard.mu.Unlock()
	}

	r.cacheServiceAnswers(svc)
}

// DeleteService removes a service and every piece of state derived
// from it. The endpoint shard is wiped unconditionally so that
// endpoints-before-Service ordering can't leave stale endpoints for
// a later AddService to pick up.
func (r *Registry) DeleteService(name, namespace string) {
	key := namespace + "/" + name
	shard := r.getServiceShard(key)
	shard.mu.Lock()
	prev := shard.services[key]
	delete(shard.services, key)
	shard.mu.Unlock()

	if prev != nil {
		r.removeServiceIPs(prev)
		r.uncacheServiceAnswers(prev)
		if prev.Headless {
			r.dropHeadlessState(prev)
		}
	}

	epShard := r.getEndpointShard(key)
	epShard.mu.Lock()
	delete(epShard.endpoints, key)
	epShard.mu.Unlock()
}

func (r *Registry) removeServiceIPs(svc *Service) {
	for _, ip := range svc.ClusterIPs {
		ipStr := net.IP(ip).String()
		if ipStr == "" || ipStr == "<nil>" {
			continue
		}
		ipShard := r.getServiceByIPShard(ipStr)
		ipShard.mu.Lock()
		if cur := ipShard.services[ipStr]; cur != nil && cur.Name == svc.Name && cur.Namespace == svc.Namespace {
			delete(ipShard.services, ipStr)
		}
		ipShard.mu.Unlock()
	}
}

func (r *Registry) serviceFQDN(svc *Service) string {
	return strings.ToLower(svc.Name) + "." + strings.ToLower(svc.Namespace) + r.svcSuffix
}

func (r *Registry) cacheServiceAnswers(svc *Service) {
	fqdn := r.serviceFQDN(svc)

	if svc.ExternalName != "" {
		// fallback makes every qtype follow the CNAME chain so
		// the resolver can chase ExternalName aliases.
		cname := []dns.RR{&dns.CNAME{
			Hdr: dns.RR_Header{
				Name:   fqdn,
				Rrtype: dns.TypeCNAME,
				Class:  dns.ClassINET,
				Ttl:    r.ttlService,
			},
			Target: dns.Fqdn(svc.ExternalName),
		}}
		r.putAnswer(fqdn, &answerSet{cname: cname, fallback: cname})
		return
	}

	if svc.Headless {
		r.rebuildHeadlessFromService(svc)
		return
	}

	set := &answerSet{}
	if ipv4 := svc.GetIPv4(); len(ipv4) > 0 {
		set.a = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{
				Name:   fqdn,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    r.ttlService,
			},
			A: ipv4,
		}}
	}
	if ipv6 := svc.GetIPv6(); len(ipv6) > 0 {
		set.aaaa = []dns.RR{&dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   fqdn,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    r.ttlService,
			},
			AAAA: ipv6,
		}}
	}
	r.putAnswer(fqdn, set)

	for _, ip := range svc.ClusterIPs {
		ptrQname := reverseQname(ip)
		if ptrQname == "" {
			continue
		}
		r.putAnswer(ptrQname, &answerSet{ptr: []dns.RR{&dns.PTR{
			Hdr: dns.RR_Header{
				Name:   ptrQname,
				Rrtype: dns.TypePTR,
				Class:  dns.ClassINET,
				Ttl:    r.ttlPTR,
			},
			Ptr: fqdn,
		}}})
	}

	srvExtra := make([]dns.RR, 0, len(set.a)+len(set.aaaa))
	srvExtra = append(srvExtra, set.a...)
	srvExtra = append(srvExtra, set.aaaa...)
	for _, p := range svc.Ports {
		if p.Name == "" || p.Protocol == "" {
			continue
		}
		srvQname := "_" + strings.ToLower(p.Name) + "._" + strings.ToLower(p.Protocol) + "." + fqdn
		r.putAnswer(srvQname, &answerSet{
			srv: []dns.RR{&dns.SRV{
				Hdr: dns.RR_Header{
					Name:   srvQname,
					Rrtype: dns.TypeSRV,
					Class:  dns.ClassINET,
					Ttl:    r.ttlSRV,
				},
				Priority: 0,
				Weight:   100,
				Port:     uint16(p.Port), //nolint:gosec // G115 - Kubernetes port is 0-65535
				Target:   fqdn,
			}},
			srvExtra: srvExtra,
		})
	}
}

// uncacheServiceAnswers clears svc's entries from the answer cache.
// Headless per-target entries are owned by the incremental state
// machinery and aren't touched here.
func (r *Registry) uncacheServiceAnswers(svc *Service) {
	fqdn := r.serviceFQDN(svc)
	r.putAnswer(fqdn, nil)
	for _, ip := range svc.ClusterIPs {
		if q := reverseQname(ip); q != "" {
			r.putAnswer(q, nil)
		}
	}
	for _, p := range svc.Ports {
		if p.Name == "" || p.Protocol == "" {
			continue
		}
		srvQname := "_" + strings.ToLower(p.Name) + "._" + strings.ToLower(p.Protocol) + "." + fqdn
		r.putAnswer(srvQname, nil)
	}
}

// reverseQname returns the in-addr.arpa / ip6.arpa name for ip, or
// "" if ip isn't a valid v4 or v16 byte slice.
func reverseQname(ip []byte) string {
	switch len(ip) {
	case net.IPv4len:
		var sb strings.Builder
		sb.Grow(net.IPv4len*4 + len(".in-addr.arpa."))
		for i := net.IPv4len - 1; i >= 0; i-- {
			sb.WriteString(strconv.Itoa(int(ip[i])))
			sb.WriteByte('.')
		}
		sb.WriteString("in-addr.arpa.")
		return sb.String()
	case net.IPv6len:
		const hex = "0123456789abcdef"
		var sb strings.Builder
		sb.Grow(net.IPv6len*4 + len(".ip6.arpa."))
		for i := net.IPv6len - 1; i >= 0; i-- {
			b := ip[i]
			sb.WriteByte(hex[b&0x0f])
			sb.WriteByte('.')
			sb.WriteByte(hex[b>>4])
			sb.WriteByte('.')
		}
		sb.WriteString("ip6.arpa.")
		return sb.String()
	}
	return ""
}

// AddPod adds or updates a pod.
func (r *Registry) AddPod(pod *Pod) {
	if pod == nil {
		zlog.Error("Attempted to add nil pod to registry")
		return
	}
	if pod.Name == "" || pod.Namespace == "" {
		zlog.Error("Attempted to add pod with empty name or namespace",
			zlog.String("name", pod.Name),
			zlog.String("namespace", pod.Namespace))
		return
	}
	if len(pod.IPs) == 0 {
		zlog.Debug("Pod has no IPs",
			zlog.String("pod", pod.Name),
			zlog.String("namespace", pod.Namespace))
		return
	}

	nameKey := pod.Namespace + "/" + pod.Name
	nameShard := r.getPodByNameShard(nameKey)
	nameShard.mu.Lock()
	prev := nameShard.pods[nameKey]
	nameShard.pods[nameKey] = pod
	nameShard.mu.Unlock()
	if prev != nil {
		r.uncachePodAnswers(prev)
		for _, ip := range prev.IPs {
			if ip == "" {
				continue
			}
			shard := r.getPodShardByIP(ip)
			shard.mu.Lock()
			if cur := shard.pods[ip]; cur != nil && cur.Name == pod.Name && cur.Namespace == pod.Namespace {
				delete(shard.pods, ip)
			}
			shard.mu.Unlock()
		}
	}

	for _, ip := range pod.IPs {
		if ip == "" {
			continue
		}
		shard := r.getPodShardByIP(ip)
		shard.mu.Lock()
		shard.pods[ip] = pod
		shard.mu.Unlock()
	}

	r.cachePodAnswers(pod)
}

// DeletePod removes a pod from every shard it was indexed in.
func (r *Registry) DeletePod(name, namespace string) {
	nameKey := namespace + "/" + name
	nameShard := r.getPodByNameShard(nameKey)
	nameShard.mu.Lock()
	pod := nameShard.pods[nameKey]
	delete(nameShard.pods, nameKey)
	nameShard.mu.Unlock()
	if pod == nil {
		return
	}
	for _, ip := range pod.IPs {
		shard := r.getPodShardByIP(ip)
		shard.mu.Lock()
		if cur := shard.pods[ip]; cur != nil && cur.Name == name && cur.Namespace == namespace {
			delete(shard.pods, ip)
		}
		shard.mu.Unlock()
	}
	r.uncachePodAnswers(pod)
}

// podIPFQDNs returns the FQDNs under which a pod IP must resolve.
// IPv6 has both compressed (2001-db8--1) and fully-expanded forms
// since clients may use either.
func (r *Registry) podIPFQDNs(ip, namespace string) []string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil
	}
	nsLower := strings.ToLower(namespace)
	if v4 := parsed.To4(); v4 != nil {
		encoded := strings.ReplaceAll(v4.String(), ".", "-")
		return []string{strings.ToLower(encoded) + "." + nsLower + r.podSuffix}
	}
	v16 := parsed.To16()
	if v16 == nil {
		return nil
	}
	compressed := strings.ToLower(strings.ReplaceAll(parsed.String(), ":", "-")) + "." + nsLower + r.podSuffix
	full := expandedIPv6Label(v16) + "." + nsLower + r.podSuffix
	if compressed == full {
		return []string{compressed}
	}
	return []string{compressed, full}
}

func expandedIPv6Label(v16 []byte) string {
	const hex = "0123456789abcdef"
	var sb strings.Builder
	sb.Grow(39)
	for i := 0; i < 8; i++ {
		if i > 0 {
			sb.WriteByte('-')
		}
		hi, lo := v16[i*2], v16[i*2+1]
		sb.WriteByte(hex[hi>>4])
		sb.WriteByte(hex[hi&0x0f])
		sb.WriteByte(hex[lo>>4])
		sb.WriteByte(hex[lo&0x0f])
	}
	return sb.String()
}

// cachePodAnswers writes IP-encoded FQDN and reverse-arpa PTR
// entries for each of pod's IPs. Per-pod service-scoped records
// come from the EndpointSlice path, not from Pod state, so that
// readiness is respected.
func (r *Registry) cachePodAnswers(pod *Pod) {
	for _, ip := range pod.IPs {
		if ip == "" {
			continue
		}
		fqdns := r.podIPFQDNs(ip, pod.Namespace)
		if len(fqdns) == 0 {
			continue
		}
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		// PTR points back at the canonical (first) FQDN, there
		// is only one PTR per IP, regardless of how many forward
		// aliases the pod has.
		canonical := fqdns[0]
		if v4 := parsed.To4(); v4 != nil {
			for _, fqdn := range fqdns {
				r.putAnswer(fqdn, &answerSet{a: []dns.RR{&dns.A{
					Hdr: dns.RR_Header{
						Name:   fqdn,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    r.ttlPod,
					},
					A: v4,
				}}})
			}
			if ptrQ := reverseQname(v4); ptrQ != "" {
				r.putAnswer(ptrQ, &answerSet{ptr: []dns.RR{&dns.PTR{
					Hdr: dns.RR_Header{
						Name:   ptrQ,
						Rrtype: dns.TypePTR,
						Class:  dns.ClassINET,
						Ttl:    r.ttlPTR,
					},
					Ptr: canonical,
				}}})
			}
		} else if v16 := parsed.To16(); v16 != nil {
			for _, fqdn := range fqdns {
				r.putAnswer(fqdn, &answerSet{aaaa: []dns.RR{&dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   fqdn,
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    r.ttlPod,
					},
					AAAA: v16,
				}}})
			}
			if ptrQ := reverseQname(v16); ptrQ != "" {
				r.putAnswer(ptrQ, &answerSet{ptr: []dns.RR{&dns.PTR{
					Hdr: dns.RR_Header{
						Name:   ptrQ,
						Rrtype: dns.TypePTR,
						Class:  dns.ClassINET,
						Ttl:    r.ttlPTR,
					},
					Ptr: canonical,
				}}})
			}
		}
	}
}

func (r *Registry) uncachePodAnswers(pod *Pod) {
	for _, ip := range pod.IPs {
		if ip == "" {
			continue
		}
		for _, fqdn := range r.podIPFQDNs(ip, pod.Namespace) {
			r.putAnswer(fqdn, nil)
		}
		if parsed := net.ParseIP(ip); parsed != nil {
			if v4 := parsed.To4(); v4 != nil {
				if q := reverseQname(v4); q != "" {
					r.putAnswer(q, nil)
				}
			} else if v16 := parsed.To16(); v16 != nil {
				if q := reverseQname(v16); q != "" {
					r.putAnswer(q, nil)
				}
			}
		}
	}
}

func (r *Registry) GetService(name, namespace string) *Service {
	key := namespace + "/" + name
	shard := r.getServiceShard(key)
	shard.mu.RLock()
	svc := shard.services[key]
	shard.mu.RUnlock()
	return svc
}

// GetServiceByIP returns the service whose ClusterIPs contain ip
// (IPv4 or IPv6 byte slice).
func (r *Registry) GetServiceByIP(ip []byte) *Service {
	ipStr := net.IP(ip).String()
	if ipStr == "" || ipStr == "<nil>" {
		return nil
	}
	shard := r.getServiceByIPShard(ipStr)
	shard.mu.RLock()
	svc := shard.services[ipStr]
	shard.mu.RUnlock()
	return svc
}

func (r *Registry) GetPodByName(name, namespace string) *Pod {
	nameKey := namespace + "/" + name
	shard := r.getPodByNameShard(nameKey)
	shard.mu.RLock()
	pod := shard.pods[nameKey]
	shard.mu.RUnlock()
	return pod
}

func (r *Registry) GetPodByIP(ip string) *Pod {
	if ip == "" {
		return nil
	}
	shard := r.getPodShardByIP(ip)
	shard.mu.RLock()
	pod := shard.pods[ip]
	shard.mu.RUnlock()
	return pod
}

func (r *Registry) getPodByNameShard(key string) *podByNameShard {
	hash := uint32(0)
	for i := 0; i < len(key); i++ {
		hash = hash*31 + uint32(key[i])
	}
	return r.podByName[hash%256]
}

func (r *Registry) getServiceByIPShard(ipStr string) *serviceByIPShard {
	hash := uint32(0)
	for i := 0; i < len(ipStr); i++ {
		hash = hash*31 + uint32(ipStr[i])
	}
	return r.serviceByIP[hash%256]
}

func (r *Registry) getServiceShard(key string) *serviceShard {
	hash := uint32(0)
	for i := 0; i < len(key); i++ {
		hash = hash*31 + uint32(key[i])
	}
	return r.serviceShards[hash%256]
}

func (r *Registry) getPodShardByIP(ip string) *podShard {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return r.podShards[0]
	}
	if ip4 := parsedIP.To4(); ip4 != nil {
		return r.podShards[ip4[3]]
	}
	if ip6 := parsedIP.To16(); ip6 != nil {
		return r.podShards[ip6[15]]
	}
	return r.podShards[0]
}

// SetEndpoints replaces a service's endpoint set. Headless services
// route through the per-slice incremental state.
func (r *Registry) SetEndpoints(service, namespace string, endpoints []Endpoint) {
	key := namespace + "/" + service
	shard := r.getEndpointShard(key)

	shard.mu.Lock()
	if len(endpoints) == 0 {
		delete(shard.endpoints, key)
	} else {
		shard.endpoints[key] = endpoints
	}
	shard.mu.Unlock()

	svc := r.GetService(service, namespace)
	if svc == nil || !svc.Headless {
		return
	}
	r.applySetEndpoints(svc, endpoints)
}

func (r *Registry) GetEndpoints(service, namespace string) []Endpoint {
	key := namespace + "/" + service
	shard := r.getEndpointShard(key)

	shard.mu.RLock()
	endpoints := shard.endpoints[key]
	shard.mu.RUnlock()

	return endpoints
}

func (r *Registry) getEndpointShard(key string) *endpointShard {
	hash := uint32(0)
	for i := 0; i < len(key); i++ {
		hash = hash*31 + uint32(key[i])
	}
	return r.endpointShards[hash%256]
}

// Stats returns counters describing the registry's contents and
// traffic since process start.
func (r *Registry) Stats() map[string]int64 {
	services := int64(0)
	pods := int64(0)
	endpointSets := int64(0)
	endpoints := int64(0)

	for i := 0; i < 256; i++ {
		r.serviceShards[i].mu.RLock()
		services += int64(len(r.serviceShards[i].services))
		r.serviceShards[i].mu.RUnlock()

		// podByName has one entry per pod regardless of IP count;
		// the IP-keyed shard would double-count dual-stack pods.
		r.podByName[i].mu.RLock()
		pods += int64(len(r.podByName[i].pods))
		r.podByName[i].mu.RUnlock()

		r.endpointShards[i].mu.RLock()
		for _, eps := range r.endpointShards[i].endpoints {
			endpoints += int64(len(eps))
		}
		endpointSets += int64(len(r.endpointShards[i].endpoints))
		r.endpointShards[i].mu.RUnlock()
	}

	queries := atomic.LoadUint64(&r.queries)
	hits := atomic.LoadUint64(&r.hits)

	var hitRate int64
	if queries > 0 {
		hitRate = int64(float64(hits) / float64(queries) * 100)
	}

	return map[string]int64{
		"services":      services,
		"pods":          pods,
		"endpoints":     endpoints,
		"endpoint_sets": endpointSets,
		"queries":       int64(queries), //nolint:gosec // G115 - counter conversion
		"hits":          int64(hits),    //nolint:gosec // G115 - counter conversion
		"shards":        256,
		"hit_rate_pct":  hitRate,
	}
}
