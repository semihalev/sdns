package kubernetes

import (
	"net"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// syntheticSliceName is the contribution name SetEndpoints uses
// when storing the full endpoint set as a single slice; per-slice
// callers use the real EndpointSlice name.
const syntheticSliceName = "_set_endpoints"

// ApplyEndpointSlice records sliceName's contribution to a headless
// service. The answer cache is NOT refreshed here, call
// MaterialiseHeadless once the burst of Apply/Remove calls has
// settled. Returns true when state actually changed.
//
// When a real slice arrives for a service whose state holds a
// synthetic-slice contribution, the synthetic is retracted first;
// otherwise the two would double-count.
func (r *Registry) ApplyEndpointSlice(svcName, namespace, sliceName string, eps []Endpoint) bool {
	svc := r.GetService(svcName, namespace)
	if svc == nil || !svc.Headless {
		r.stashSliceForLaterReplay(svcName, namespace, sliceName, eps)
		return false
	}
	state := r.getOrCreateHeadlessState(svc)
	state.mu.Lock()
	defer state.mu.Unlock()

	if sliceName != syntheticSliceName {
		if synthetic, has := state.contribs[syntheticSliceName]; has {
			state.applySliceDelta(syntheticSliceName, synthetic, nil, r.ttlService)
			delete(state.contribs, syntheticSliceName)
		}
	}

	prev := state.contribs[sliceName]
	if endpointsExactEqual(prev, eps) {
		return false
	}
	state.applySliceDelta(sliceName, prev, eps, r.ttlService)
	state.contribs[sliceName] = cloneEndpoints(eps)
	return true
}

// RemoveEndpointSlice retracts sliceName's contribution. Returns
// true when state changed.
func (r *Registry) RemoveEndpointSlice(svcName, namespace, sliceName string) bool {
	svc := r.GetService(svcName, namespace)
	if svc == nil || !svc.Headless {
		return false
	}
	shard := r.getHeadlessShard(namespace + "/" + svcName)
	shard.mu.Lock()
	state, ok := shard.states[namespace+"/"+svcName]
	shard.mu.Unlock()
	if !ok {
		return false
	}
	state.mu.Lock()
	defer state.mu.Unlock()

	prev, present := state.contribs[sliceName]
	if !present {
		return false
	}
	state.applySliceDelta(sliceName, prev, nil, r.ttlService)
	delete(state.contribs, sliceName)
	return true
}

// MaterialiseHeadless rebuilds the answer cache from the headless
// state. Worker callers debounce so a flurry of Apply/Remove calls
// amortises to one materialise per debounce window.
func (r *Registry) MaterialiseHeadless(svcName, namespace string) {
	svc := r.GetService(svcName, namespace)
	if svc == nil || !svc.Headless {
		return
	}
	shard := r.getHeadlessShard(namespace + "/" + svcName)
	shard.mu.Lock()
	state, ok := shard.states[namespace+"/"+svcName]
	shard.mu.Unlock()
	if !ok {
		return
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	r.materialiseHeadlessLocked(svc, state)
}

// dropHeadlessState removes the per-service state and every cached
// entry materialise produced. Called on DeleteService and on
// headless→ClusterIP transitions.
func (r *Registry) dropHeadlessState(svc *Service) {
	key := svc.Namespace + "/" + svc.Name
	shard := r.getHeadlessShard(key)
	shard.mu.Lock()
	state, ok := shard.states[key]
	if ok {
		delete(shard.states, key)
	}
	shard.mu.Unlock()
	if !ok {
		return
	}

	state.mu.Lock()
	defer state.mu.Unlock()

	r.putAnswer(state.fqdn, nil)
	for target := range state.refs {
		r.putAnswer(target, nil)
	}
	for srvQname := range state.srvByPort {
		r.putAnswer(srvQname, nil)
	}
}

// rebuildHeadlessFromService reseeds the per-slice state from the
// endpoint shard's current snapshot and forces a complete
// materialise so the empty NOERROR/NODATA aggregate gets published
// even when there are no endpoints yet.
func (r *Registry) rebuildHeadlessFromService(svc *Service) {
	endpoints := r.GetEndpoints(svc.Name, svc.Namespace)
	state := r.getOrCreateHeadlessState(svc)
	state.mu.Lock()
	defer state.mu.Unlock()

	state.svc = svc
	state.fqdn = r.serviceFQDN(svc)
	state.ttlSvc = r.ttlService
	state.ttlSRVval = r.ttlSRV

	prev := state.contribs[syntheticSliceName]
	if !endpointsExactEqual(prev, endpoints) {
		state.applySliceDelta(syntheticSliceName, prev, endpoints, r.ttlService)
		if len(endpoints) == 0 {
			delete(state.contribs, syntheticSliceName)
		} else {
			state.contribs[syntheticSliceName] = cloneEndpoints(endpoints)
		}
	}

	state.aggregateDirty = true
	state.targetSetDirty = true
	r.materialiseHeadlessLocked(svc, state)
}

// applySetEndpoints is SetEndpoints' headless code path. Diffs the
// new endpoint set against state.refs (the cached prev) so the RR
// allocation cost stays O(delta).
func (r *Registry) applySetEndpoints(svc *Service, endpoints []Endpoint) {
	state := r.getOrCreateHeadlessState(svc)
	state.mu.Lock()
	defer state.mu.Unlock()

	state.svc = svc
	state.fqdn = r.serviceFQDN(svc)
	state.ttlSvc = r.ttlService
	state.ttlSRVval = r.ttlSRV

	for sliceName, prev := range state.contribs {
		if sliceName == syntheticSliceName {
			continue
		}
		state.applySliceDelta(sliceName, prev, nil, r.ttlService)
		delete(state.contribs, sliceName)
	}

	if endpointsExactEqual(state.contribs[syntheticSliceName], endpoints) {
		return
	}

	nextPairs := readyPairsFromEndpoints(endpoints, state.fqdn)

	for target, ips := range state.refs {
		nextIPs := nextPairs[target]
		for ip := range ips {
			if _, present := nextIPs[ip]; present {
				continue
			}
			state.removePair(target, ip)
		}
	}
	for target, ips := range nextPairs {
		prevIPs := state.refs[target]
		for ip := range ips {
			if _, present := prevIPs[ip]; present {
				continue
			}
			state.addPair(target, ip, r.ttlService)
		}
	}

	if len(endpoints) == 0 {
		delete(state.contribs, syntheticSliceName)
	} else {
		state.contribs[syntheticSliceName] = cloneEndpoints(endpoints)
	}
	r.materialiseHeadlessLocked(svc, state)
}

// stashSliceForLaterReplay handles the endpoints-before-service
// case by merging the slice into the endpoint shard so a later
// AddService can pick them up via GetEndpoints.
func (r *Registry) stashSliceForLaterReplay(svcName, namespace, _ string, eps []Endpoint) {
	key := namespace + "/" + svcName
	shard := r.getEndpointShard(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	current := shard.endpoints[key]
	merged := append(current[:0:0], current...) //nolint:gocritic // intentional copy
	merged = append(merged, eps...)
	if len(merged) == 0 {
		delete(shard.endpoints, key)
	} else {
		shard.endpoints[key] = merged
	}
}

func (r *Registry) getOrCreateHeadlessState(svc *Service) *headlessSliceState {
	key := svc.Namespace + "/" + svc.Name
	shard := r.getHeadlessShard(key)
	shard.mu.Lock()
	state, ok := shard.states[key]
	if !ok {
		state = &headlessSliceState{
			contribs:      map[string][]Endpoint{},
			refs:          map[string]map[string]int{},
			aggA:          map[string]*dns.A{},
			aggAAAA:       map[string]*dns.AAAA{},
			perTargetA:    map[string]map[string]*dns.A{},
			perTargetAAAA: map[string]map[string]*dns.AAAA{},
			srvByPort:     map[string]map[string]*dns.SRV{},
			svc:           svc,
			fqdn:          r.serviceFQDN(svc),
			ttlSvc:        r.ttlService,
			ttlSRVval:     r.ttlSRV,
		}
		shard.states[key] = state
	}
	shard.mu.Unlock()
	return state
}

func (r *Registry) getHeadlessShard(key string) *headlessShard {
	hash := uint32(0)
	for i := 0; i < len(key); i++ {
		hash = hash*31 + uint32(key[i])
	}
	return r.headlessShards[hash%256]
}

// applySliceDelta updates refs and per-target maps for the slice's
// prev → next transition; O(|prev| + |next|).
func (s *headlessSliceState) applySliceDelta(_ string, prev, next []Endpoint, ttl uint32) {
	prevPairs := readyPairsFromEndpoints(prev, s.fqdn)
	nextPairs := readyPairsFromEndpoints(next, s.fqdn)

	for target, ips := range prevPairs {
		nextIPs := nextPairs[target]
		for ip := range ips {
			if _, present := nextIPs[ip]; present {
				continue
			}
			s.removePair(target, ip)
		}
	}
	for target, ips := range nextPairs {
		prevIPs := prevPairs[target]
		for ip := range ips {
			if _, present := prevIPs[ip]; present {
				continue
			}
			s.addPair(target, ip, ttl)
		}
	}
}

func (s *headlessSliceState) addPair(target, ip string, ttl uint32) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return
	}
	targetRefs, ok := s.refs[target]
	if !ok {
		targetRefs = map[string]int{}
		s.refs[target] = targetRefs
		s.targetOrder = nil
		s.targetSetDirty = true
	}
	wasPresent := targetRefs[ip] > 0
	targetRefs[ip]++
	if wasPresent {
		return
	}
	if s.dirtyTargets == nil {
		s.dirtyTargets = map[string]struct{}{}
	}
	s.dirtyTargets[target] = struct{}{}
	if v4 := parsed.To4(); v4 != nil {
		if _, exists := s.aggA[ip]; !exists {
			s.aggA[ip] = &dns.A{
				Hdr: dns.RR_Header{Name: s.fqdn, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
				A:   v4,
			}
			s.aggregateDirty = true
		}
		perT, ok := s.perTargetA[target]
		if !ok {
			perT = map[string]*dns.A{}
			s.perTargetA[target] = perT
		}
		perT[ip] = &dns.A{
			Hdr: dns.RR_Header{Name: target, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
			A:   v4,
		}
	} else if v16 := parsed.To16(); v16 != nil {
		if _, exists := s.aggAAAA[ip]; !exists {
			s.aggAAAA[ip] = &dns.AAAA{
				Hdr:  dns.RR_Header{Name: s.fqdn, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
				AAAA: v16,
			}
			s.aggregateDirty = true
		}
		perT, ok := s.perTargetAAAA[target]
		if !ok {
			perT = map[string]*dns.AAAA{}
			s.perTargetAAAA[target] = perT
		}
		perT[ip] = &dns.AAAA{
			Hdr:  dns.RR_Header{Name: target, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
			AAAA: v16,
		}
	}
}

func (s *headlessSliceState) removePair(target, ip string) {
	targetRefs, ok := s.refs[target]
	if !ok {
		return
	}
	if targetRefs[ip] <= 1 {
		delete(targetRefs, ip)
		delete(s.perTargetA[target], ip)
		delete(s.perTargetAAAA[target], ip)
		if len(s.perTargetA[target]) == 0 {
			delete(s.perTargetA, target)
		}
		if len(s.perTargetAAAA[target]) == 0 {
			delete(s.perTargetAAAA, target)
		}
		if s.dirtyTargets == nil {
			s.dirtyTargets = map[string]struct{}{}
		}
		s.dirtyTargets[target] = struct{}{}
		if len(targetRefs) == 0 {
			delete(s.refs, target)
			s.targetOrder = nil
			s.targetSetDirty = true
			for srvQname, byTarget := range s.srvByPort {
				delete(byTarget, target)
				if len(byTarget) == 0 {
					delete(s.srvByPort, srvQname)
				}
			}
			if s.pendingClears == nil {
				s.pendingClears = map[string]struct{}{}
			}
			s.pendingClears[target] = struct{}{}
		}
		if !s.aggregateStillHasIP(ip) {
			delete(s.aggA, ip)
			delete(s.aggAAAA, ip)
			s.aggregateDirty = true
		}
	} else {
		targetRefs[ip]--
	}
}

func (s *headlessSliceState) aggregateStillHasIP(ip string) bool {
	for _, ips := range s.refs {
		if _, ok := ips[ip]; ok {
			return true
		}
	}
	return false
}

// materialiseHeadlessLocked rebuilds the answer cache from state's
// dirty bits. RR allocation is O(delta); slice-header construction
// is O(state) for the dirty dimensions and is the unavoidable cost
// of pre-built slices feeding a zero-alloc query path.
func (r *Registry) materialiseHeadlessLocked(svc *Service, state *headlessSliceState) {
	state.svc = svc
	state.fqdn = r.serviceFQDN(svc)
	state.ttlSvc = r.ttlService
	state.ttlSRVval = r.ttlSRV
	fqdn := state.fqdn

	portsHash := hashServicePorts(svc.Ports)
	portsChanged := portsHash != state.portsHash
	state.portsHash = portsHash

	if state.targetOrder == nil {
		state.targetOrder = make([]string, 0, len(state.refs))
		for target := range state.refs {
			state.targetOrder = append(state.targetOrder, target)
		}
		sort.Strings(state.targetOrder)
	}

	srvLayerDirty := state.targetSetDirty || portsChanged

	if state.aggregateDirty {
		aggSet := &answerSet{}
		if len(state.aggA) > 0 {
			aggSet.a = make([]dns.RR, 0, len(state.aggA))
			for _, rr := range state.aggA {
				aggSet.a = append(aggSet.a, rr)
			}
		}
		if len(state.aggAAAA) > 0 {
			aggSet.aaaa = make([]dns.RR, 0, len(state.aggAAAA))
			for _, rr := range state.aggAAAA {
				aggSet.aaaa = append(aggSet.aaaa, rr)
			}
		}
		r.putAnswer(fqdn, aggSet)
	}

	for target := range state.dirtyTargets {
		if _, alive := state.refs[target]; !alive {
			continue
		}
		ts := &answerSet{}
		if pa := state.perTargetA[target]; len(pa) > 0 {
			ts.a = make([]dns.RR, 0, len(pa))
			for _, rr := range pa {
				ts.a = append(ts.a, rr)
			}
		}
		if pa := state.perTargetAAAA[target]; len(pa) > 0 {
			ts.aaaa = make([]dns.RR, 0, len(pa))
			for _, rr := range pa {
				ts.aaaa = append(ts.aaaa, rr)
			}
		}
		r.putAnswer(target, ts)
	}

	// SRV glue depends on every target's per-target pointer set,
	// so a per-target IP swap that doesn't move the global aggregate
	// (an IP shared with another target was dropped from one) still
	// invalidates the cached glue.
	glueStale := state.aggregateDirty || len(state.dirtyTargets) > 0
	if srvLayerDirty || glueStale {
		var srvExtra []dns.RR
		for _, target := range state.targetOrder {
			for _, rr := range state.perTargetA[target] {
				srvExtra = append(srvExtra, rr)
			}
			for _, rr := range state.perTargetAAAA[target] {
				srvExtra = append(srvExtra, rr)
			}
		}

		if srvLayerDirty {
			// Reuse cached *dns.SRV pointers when (target, port)
			// survives; allocate fresh on a port-number edit so
			// concurrent SRV queries don't see in-place mutation.
			wanted := map[string]struct{}{}
			for _, p := range svc.Ports {
				if p.Name == "" || p.Protocol == "" {
					continue
				}
				srvQname := "_" + strings.ToLower(p.Name) + "._" + strings.ToLower(p.Protocol) + "." + fqdn
				wanted[srvQname] = struct{}{}
				wantPort := uint16(p.Port) //nolint:gosec // G115 - Kubernetes port is 0-65535
				byTarget, ok := state.srvByPort[srvQname]
				if !ok {
					byTarget = map[string]*dns.SRV{}
					state.srvByPort[srvQname] = byTarget
				}
				set := &answerSet{
					srv:      make([]dns.RR, 0, len(state.targetOrder)),
					srvExtra: srvExtra,
				}
				for _, target := range state.targetOrder {
					rr, present := byTarget[target]
					if !present || rr.Port != wantPort {
						rr = &dns.SRV{
							Hdr: dns.RR_Header{
								Name:   srvQname,
								Rrtype: dns.TypeSRV,
								Class:  dns.ClassINET,
								Ttl:    state.ttlSRVval,
							},
							Priority: 0,
							Weight:   100,
							Port:     wantPort,
							Target:   target,
						}
						byTarget[target] = rr
					}
					set.srv = append(set.srv, rr)
				}
				r.putAnswer(srvQname, set)
			}
			for srvQname := range state.srvByPort {
				if _, ok := wanted[srvQname]; !ok {
					r.putAnswer(srvQname, nil)
					delete(state.srvByPort, srvQname)
				}
			}
		} else {
			// Target set unchanged: reuse the existing srv slice
			// alongside fresh srvExtra in a new answerSet so we
			// don't mutate a published set in place.
			for srvQname := range state.srvByPort {
				old := r.peekAnswer(srvQname)
				if old == nil {
					continue
				}
				r.putAnswer(srvQname, &answerSet{
					srv:      old.srv,
					srvExtra: srvExtra,
				})
			}
		}
	}

	for target := range state.pendingClears {
		if _, alive := state.refs[target]; alive {
			continue
		}
		r.putAnswer(target, nil)
	}
	state.pendingClears = nil
	state.dirtyTargets = nil
	state.aggregateDirty = false
	state.targetSetDirty = false
}

// hashServicePorts fingerprints the named-port set so materialise
// can detect port edits between rebuilds.
func hashServicePorts(ports []Port) uint64 {
	h := uint64(1469598103934665603)
	const prime = 1099511628211
	for _, p := range ports {
		for _, b := range []byte(p.Name) {
			h ^= uint64(b)
			h *= prime
		}
		h ^= '|'
		h *= prime
		for _, b := range []byte(p.Protocol) {
			h ^= uint64(b)
			h *= prime
		}
		h ^= '|'
		h *= prime
		port := uint32(p.Port) //nolint:gosec // G115 - Kubernetes port is 0-65535
		for i := 0; i < 4; i++ {
			h ^= uint64(byte(port >> (i * 8)))
			h *= prime
		}
		h ^= '\n'
		h *= prime
	}
	return h
}

func (r *Registry) peekAnswer(qname string) *answerSet {
	shard := r.getAnswerShard(qname)
	shard.mu.RLock()
	set := shard.entries[qname]
	shard.mu.RUnlock()
	return set
}

// readyPairsFromEndpoints converts ready endpoints to a target → ip
// set. Hostnamed endpoints share one target; anonymous endpoints
// get one target per address.
func readyPairsFromEndpoints(eps []Endpoint, fqdn string) map[string]map[string]struct{} {
	if len(eps) == 0 {
		return nil
	}
	out := make(map[string]map[string]struct{}, len(eps))
	for _, ep := range eps {
		if !ep.Ready {
			continue
		}
		var hostnameTarget string
		if ep.Hostname != "" {
			hostnameTarget = strings.ToLower(ep.Hostname) + "." + fqdn
		}
		for _, a := range ep.Addresses {
			ip := net.ParseIP(a)
			if ip == nil {
				continue
			}
			target := hostnameTarget
			if target == "" {
				target = dashedIPLabel(ip) + "." + fqdn
			}
			ipStr := ip.String()
			set, ok := out[target]
			if !ok {
				set = map[string]struct{}{}
				out[target] = set
			}
			set[ipStr] = struct{}{}
		}
	}
	return out
}

// dashedIPLabel returns the dash-encoded form of ip suitable as a
// single DNS label (10.0.0.1 → "10-0-0-1", 2001:db8::1 → "2001-db8--1").
func dashedIPLabel(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return strings.ReplaceAll(v4.String(), ".", "-")
	}
	return strings.ToLower(strings.ReplaceAll(ip.String(), ":", "-"))
}

func endpointsExactEqual(a, b []Endpoint) bool {
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
	}
	return true
}

func cloneEndpoints(eps []Endpoint) []Endpoint {
	if len(eps) == 0 {
		return nil
	}
	out := make([]Endpoint, len(eps))
	for i, ep := range eps {
		out[i] = ep
		if len(ep.Addresses) > 0 {
			out[i].Addresses = append([]string(nil), ep.Addresses...)
		}
	}
	return out
}
