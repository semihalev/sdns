package kubernetes

import (
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// SmartPredictor uses intelligent pattern recognition for Kubernetes DNS
type SmartPredictor struct {
	// Service dependency graph
	serviceDeps *ServiceDependencyGraph

	// Time-based patterns
	timePatterns *TimeBasedPatterns

	// Client behavior profiles
	clientProfiles *ClientProfiles

	// Namespace patterns (services in same namespace often queried together)
	namespaceCorrelation *NamespaceCorrelation

	// Performance metrics
	predictions uint64
	hits        uint64
}

// ServiceDependencyGraph tracks which services are queried together
type ServiceDependencyGraph struct {
	edges map[string]*ServiceNode // service name -> node
	mu    sync.RWMutex
}

type ServiceNode struct {
	name         string
	dependencies map[string]*DependencyInfo // dependent service -> info
	lastAccess   int64
}

type DependencyInfo struct {
	count      uint32  // How many times B was queried after A
	totalTime  int64   // Total time between queries (for avg calculation)
	lastSeen   int64   // Last time this pattern was seen
	confidence float64 // Confidence score (0-1)
}

// TimeBasedPatterns recognizes temporal patterns
type TimeBasedPatterns struct {
	hourlyPatterns [24]*HourPattern // Patterns for each hour of day
	weekPatterns   [7]*DayPattern   // Patterns for each day of week
	mu             sync.RWMutex
}

type HourPattern struct {
	topServices []WeightedService
	queryCount  uint64
}

type DayPattern struct {
	topServices []WeightedService
	queryCount  uint64
}

type WeightedService struct {
	name   string
	weight float64
}

// ClientProfiles tracks per-client query patterns
type ClientProfiles struct {
	profiles sync.Map // client IP -> *ClientProfile
}

type ClientProfile struct {
	recentQueries *RingBuffer
	queryPatterns map[string]uint32
	lastSeen      int64
	mu            sync.RWMutex // Protect queryPatterns map
}

// NamespaceCorrelation tracks services queried together in same namespace
type NamespaceCorrelation struct {
	correlations map[string]*NamespaceInfo // namespace -> info
	mu           sync.RWMutex
}

type NamespaceInfo struct {
	serviceGraph map[string]map[string]uint32 // service -> related services -> count
	lastUpdate   int64
}

// RingBuffer for efficient recent query tracking
type RingBuffer struct {
	items []QueryRecord
	head  int
	size  int
	mu    sync.Mutex
}

type QueryRecord struct {
	service   string
	timestamp int64
	qtype     uint16
}

// NewSmartPredictor creates an intelligent predictor
func NewSmartPredictor() *SmartPredictor {
	sp := &SmartPredictor{
		serviceDeps: &ServiceDependencyGraph{
			edges: make(map[string]*ServiceNode),
		},
		timePatterns:   &TimeBasedPatterns{},
		clientProfiles: &ClientProfiles{},
		namespaceCorrelation: &NamespaceCorrelation{
			correlations: make(map[string]*NamespaceInfo),
		},
	}

	// Initialize time patterns
	for i := 0; i < 24; i++ {
		sp.timePatterns.hourlyPatterns[i] = &HourPattern{}
	}
	for i := 0; i < 7; i++ {
		sp.timePatterns.weekPatterns[i] = &DayPattern{}
	}

	// Start pattern analysis goroutine
	go sp.analyzePatterns()

	return sp
}

// Record records a query and updates patterns
func (sp *SmartPredictor) Record(clientIP, service string, qtype uint16) {
	now := time.Now()

	// Update service dependency graph
	sp.updateServiceDependencies(clientIP, service, now)

	// Update time-based patterns
	sp.updateTimePatterns(service, now)

	// Update client profile
	sp.updateClientProfile(clientIP, service, qtype, now)

	// Update namespace correlations
	sp.updateNamespaceCorrelations(service, now)
}

// Predict returns services likely to be queried next
func (sp *SmartPredictor) Predict(clientIP, currentService string) []PredictedService {
	atomic.AddUint64(&sp.predictions, 1)

	predictions := make(map[string]float64)

	// Get predictions from service dependencies
	sp.addServiceDependencyPredictions(currentService, predictions)

	// Get predictions from time patterns
	sp.addTimeBasedPredictions(predictions)

	// Get predictions from client profile
	sp.addClientProfilePredictions(clientIP, predictions)

	// Get predictions from namespace correlations
	sp.addNamespaceCorrelationPredictions(currentService, predictions)

	// Sort by confidence and return top predictions
	return sp.getTopPredictions(predictions, 5)
}

// Update methods

func (sp *SmartPredictor) updateServiceDependencies(clientIP, service string, now time.Time) {
	sp.serviceDeps.mu.Lock()
	defer sp.serviceDeps.mu.Unlock()

	// Get or create service node
	node, exists := sp.serviceDeps.edges[service]
	if !exists {
		node = &ServiceNode{
			name:         service,
			dependencies: make(map[string]*DependencyInfo),
			lastAccess:   now.Unix(),
		}
		sp.serviceDeps.edges[service] = node
	}

	// Update dependencies based on recent queries from this client
	if profile := sp.getClientProfile(clientIP); profile != nil {
		recent := profile.recentQueries.GetRecent(5)
		for _, query := range recent {
			if query.service != service && now.Unix()-query.timestamp < 5 {
				// Services queried within 5 seconds are likely related
				dep, exists := node.dependencies[query.service]
				if !exists {
					dep = &DependencyInfo{}
					node.dependencies[query.service] = dep
				}

				atomic.AddUint32(&dep.count, 1)
				timeDiff := now.Unix() - query.timestamp
				atomic.AddInt64(&dep.totalTime, timeDiff)
				atomic.StoreInt64(&dep.lastSeen, now.Unix())

				// Update confidence based on frequency and recency
				dep.confidence = sp.calculateConfidence(dep)
			}
		}
	}

	node.lastAccess = now.Unix()
}

func (sp *SmartPredictor) updateTimePatterns(service string, now time.Time) {
	hour := now.Hour()
	day := int(now.Weekday())

	sp.timePatterns.mu.Lock()
	defer sp.timePatterns.mu.Unlock()

	// Update hourly pattern
	hourPattern := sp.timePatterns.hourlyPatterns[hour]
	atomic.AddUint64(&hourPattern.queryCount, 1)
	sp.updateServiceWeight(hourPattern, service)

	// Update daily pattern
	dayPattern := sp.timePatterns.weekPatterns[day]
	atomic.AddUint64(&dayPattern.queryCount, 1)
	sp.updateServiceWeight(dayPattern, service)
}

func (sp *SmartPredictor) updateClientProfile(clientIP, service string, qtype uint16, now time.Time) {
	profileI, _ := sp.clientProfiles.profiles.LoadOrStore(clientIP, &ClientProfile{
		recentQueries: NewRingBuffer(20),
		queryPatterns: make(map[string]uint32),
		lastSeen:      now.Unix(),
	})

	profile := profileI.(*ClientProfile)

	// Add to recent queries
	profile.recentQueries.Add(QueryRecord{
		service:   service,
		timestamp: now.Unix(),
		qtype:     qtype,
	})

	// Update query patterns (protected by mutex)
	profile.mu.Lock()
	profile.queryPatterns[service]++
	profile.mu.Unlock()
	atomic.StoreInt64(&profile.lastSeen, now.Unix())
}

func (sp *SmartPredictor) updateNamespaceCorrelations(service string, now time.Time) {
	// Extract namespace from service name
	namespace := extractNamespace(service)
	if namespace == "" {
		return
	}

	sp.namespaceCorrelation.mu.Lock()
	defer sp.namespaceCorrelation.mu.Unlock()

	nsInfo, exists := sp.namespaceCorrelation.correlations[namespace]
	if !exists {
		nsInfo = &NamespaceInfo{
			serviceGraph: make(map[string]map[string]uint32),
			lastUpdate:   now.Unix(),
		}
		sp.namespaceCorrelation.correlations[namespace] = nsInfo
	}

	// Update correlation with other services in namespace
	baseService := extractServiceName(service)
	if _, exists := nsInfo.serviceGraph[baseService]; !exists {
		nsInfo.serviceGraph[baseService] = make(map[string]uint32)
	}

	nsInfo.lastUpdate = now.Unix()
}

// Prediction methods

func (sp *SmartPredictor) addServiceDependencyPredictions(currentService string, predictions map[string]float64) {
	sp.serviceDeps.mu.RLock()
	defer sp.serviceDeps.mu.RUnlock()

	node, exists := sp.serviceDeps.edges[currentService]
	if !exists {
		return
	}

	// Add predictions based on service dependencies
	for depService, depInfo := range node.dependencies {
		if depInfo.confidence > 0.3 { // Only include high-confidence predictions
			predictions[depService] += depInfo.confidence * 0.4 // 40% weight
		}
	}

	// Also check reverse dependencies (if B depends on A, and we're querying A, B might be next)
	for serviceName, serviceNode := range sp.serviceDeps.edges {
		if dep, exists := serviceNode.dependencies[currentService]; exists && dep.confidence > 0.3 {
			predictions[serviceName] += dep.confidence * 0.2 // 20% weight for reverse
		}
	}
}

func (sp *SmartPredictor) addTimeBasedPredictions(predictions map[string]float64) {
	now := time.Now()
	hour := now.Hour()
	day := int(now.Weekday())

	sp.timePatterns.mu.RLock()
	defer sp.timePatterns.mu.RUnlock()

	// Add hourly pattern predictions
	hourPattern := sp.timePatterns.hourlyPatterns[hour]
	for _, ws := range hourPattern.topServices {
		predictions[ws.name] += ws.weight * 0.2 // 20% weight
	}

	// Add daily pattern predictions
	dayPattern := sp.timePatterns.weekPatterns[day]
	for _, ws := range dayPattern.topServices {
		predictions[ws.name] += ws.weight * 0.1 // 10% weight
	}
}

func (sp *SmartPredictor) addClientProfilePredictions(clientIP string, predictions map[string]float64) {
	profileI, exists := sp.clientProfiles.profiles.Load(clientIP)
	if !exists {
		return
	}

	profile := profileI.(*ClientProfile)

	// Get frequently queried services by this client
	type serviceCount struct {
		name  string
		count uint32
	}

	var services []serviceCount
	profile.mu.RLock()
	for service, count := range profile.queryPatterns {
		services = append(services, serviceCount{service, count})
	}
	profile.mu.RUnlock()

	// Sort by count
	sort.Slice(services, func(i, j int) bool {
		return services[i].count > services[j].count
	})

	// Add top services to predictions
	totalCount := uint32(0)
	for _, sc := range services {
		totalCount += sc.count
	}

	for i := 0; i < len(services) && i < 5; i++ {
		weight := float64(services[i].count) / float64(totalCount)
		predictions[services[i].name] += weight * 0.3 // 30% weight
	}
}

func (sp *SmartPredictor) addNamespaceCorrelationPredictions(currentService string, predictions map[string]float64) {
	namespace := extractNamespace(currentService)
	if namespace == "" {
		return
	}

	sp.namespaceCorrelation.mu.RLock()
	defer sp.namespaceCorrelation.mu.RUnlock()

	nsInfo, exists := sp.namespaceCorrelation.correlations[namespace]
	if !exists {
		return
	}

	baseService := extractServiceName(currentService)

	// Find related services in the same namespace
	for service, relatedServices := range nsInfo.serviceGraph {
		if service == baseService {
			continue
		}

		// Check if services are related
		if count, exists := relatedServices[baseService]; exists {
			weight := math.Min(float64(count)/100.0, 1.0) // Normalize
			fullServiceName := service + "." + namespace + ".svc.cluster.local."
			predictions[fullServiceName] += weight * 0.1 // 10% weight
		}
	}
}

// Helper methods

func (sp *SmartPredictor) calculateConfidence(dep *DependencyInfo) float64 {
	// Factors:
	// 1. Frequency (how often this pattern occurs)
	// 2. Recency (how recently we've seen this pattern)
	// 3. Consistency (average time between queries)

	count := atomic.LoadUint32(&dep.count)
	lastSeen := atomic.LoadInt64(&dep.lastSeen)
	totalTime := atomic.LoadInt64(&dep.totalTime)

	// Frequency score (logarithmic scale)
	freqScore := math.Min(math.Log10(float64(count)+1)/2, 1.0)

	// Recency score (exponential decay over hours)
	hoursSinceLastSeen := float64(time.Now().Unix()-lastSeen) / 3600
	recencyScore := math.Exp(-hoursSinceLastSeen / 24) // 24-hour half-life

	// Consistency score (lower variance = higher score)
	avgTime := float64(totalTime) / float64(count)
	consistencyScore := 1.0 / (1.0 + avgTime/5.0) // Normalize around 5 seconds

	// Combined confidence
	return (freqScore*0.5 + recencyScore*0.3 + consistencyScore*0.2)
}

func (sp *SmartPredictor) getTopPredictions(predictions map[string]float64, n int) []PredictedService {
	// Convert to slice for sorting
	var results []PredictedService
	for service, score := range predictions {
		if score > 0.1 { // Minimum threshold
			results = append(results, PredictedService{
				Service:    service,
				Confidence: score,
			})
		}
	}

	// Sort by confidence
	sort.Slice(results, func(i, j int) bool {
		return results[i].Confidence > results[j].Confidence
	})

	// Return top N
	if len(results) > n {
		results = results[:n]
	}

	// Track hits for metrics
	if len(results) > 0 {
		atomic.AddUint64(&sp.hits, 1)
	}

	return results
}

func (sp *SmartPredictor) analyzePatterns() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		// Clean up old data
		sp.cleanupOldData()

		// Analyze patterns for better predictions
		sp.analyzeServicePatterns()

		// Update confidence scores
		sp.updateConfidenceScores()
	}
}

func (sp *SmartPredictor) cleanupOldData() {
	now := time.Now().Unix()

	// Clean up old service dependencies
	sp.serviceDeps.mu.Lock()
	for service, node := range sp.serviceDeps.edges {
		// Remove old dependencies
		for depService, depInfo := range node.dependencies {
			if now-depInfo.lastSeen > 86400 { // 24 hours
				delete(node.dependencies, depService)
			}
		}

		// Remove nodes not accessed in 7 days
		if now-node.lastAccess > 604800 {
			delete(sp.serviceDeps.edges, service)
		}
	}
	sp.serviceDeps.mu.Unlock()

	// Clean up old client profiles
	sp.clientProfiles.profiles.Range(func(key, value interface{}) bool {
		profile := value.(*ClientProfile)
		if now-profile.lastSeen > 3600 { // 1 hour
			sp.clientProfiles.profiles.Delete(key)
		}
		return true
	})
}

func (sp *SmartPredictor) analyzeServicePatterns() {
	// Implement pattern analysis to identify:
	// 1. Service call chains (A -> B -> C)
	// 2. Periodic patterns (cron jobs, health checks)
	// 3. Burst patterns (deployment, scaling events)
	// This is where more sophisticated ML could be added
}

func (sp *SmartPredictor) updateConfidenceScores() {
	sp.serviceDeps.mu.Lock()
	defer sp.serviceDeps.mu.Unlock()

	// Recalculate confidence scores based on latest data
	for _, node := range sp.serviceDeps.edges {
		for _, depInfo := range node.dependencies {
			depInfo.confidence = sp.calculateConfidence(depInfo)
		}
	}
}

// Stats returns predictor statistics
func (sp *SmartPredictor) Stats() map[string]interface{} {
	sp.serviceDeps.mu.RLock()
	serviceCount := len(sp.serviceDeps.edges)
	edgeCount := 0
	for _, node := range sp.serviceDeps.edges {
		edgeCount += len(node.dependencies)
	}
	sp.serviceDeps.mu.RUnlock()

	clientCount := 0
	sp.clientProfiles.profiles.Range(func(_, _ interface{}) bool {
		clientCount++
		return true
	})

	predictions := atomic.LoadUint64(&sp.predictions)
	hits := atomic.LoadUint64(&sp.hits)

	accuracy := float64(0)
	if predictions > 0 {
		accuracy = float64(hits) / float64(predictions) * 100
	}

	return map[string]interface{}{
		"services":    serviceCount,
		"edges":       edgeCount,
		"clients":     clientCount,
		"predictions": predictions,
		"hits":        hits,
		"accuracy":    accuracy,
	}
}

// Helper functions

func extractNamespace(service string) string {
	// Extract namespace from service.namespace.svc.cluster.local
	parts := dns.SplitDomainName(service)
	if len(parts) >= 5 && parts[2] == "svc" {
		return parts[1]
	}
	return ""
}

func extractServiceName(service string) string {
	// Extract service name from service.namespace.svc.cluster.local
	parts := dns.SplitDomainName(service)
	if len(parts) >= 5 && parts[2] == "svc" {
		return parts[0]
	}
	return service
}

func (sp *SmartPredictor) updateServiceWeight(pattern interface{}, service string) {
	// Update or add service weight
	// This is simplified - in production, use a more sophisticated algorithm
	switch p := pattern.(type) {
	case *HourPattern:
		found := false
		for i, ws := range p.topServices {
			if ws.name == service {
				p.topServices[i].weight += 0.1
				found = true
				break
			}
		}

		if !found && len(p.topServices) < 10 {
			p.topServices = append(p.topServices, WeightedService{
				name:   service,
				weight: 0.1,
			})
		}
	case *DayPattern:
		found := false
		for i, ws := range p.topServices {
			if ws.name == service {
				p.topServices[i].weight += 0.1
				found = true
				break
			}
		}

		if !found && len(p.topServices) < 10 {
			p.topServices = append(p.topServices, WeightedService{
				name:   service,
				weight: 0.1,
			})
		}
	}
}

func (sp *SmartPredictor) getClientProfile(clientIP string) *ClientProfile {
	if profileI, exists := sp.clientProfiles.profiles.Load(clientIP); exists {
		return profileI.(*ClientProfile)
	}
	return nil
}

// PredictedService represents a predicted service with confidence
type PredictedService struct {
	Service    string
	Confidence float64
	Reason     string // Why this was predicted (for debugging)
}

// RingBuffer implementation

func NewRingBuffer(size int) *RingBuffer {
	return &RingBuffer{
		items: make([]QueryRecord, size),
		size:  size,
	}
}

func (rb *RingBuffer) Add(record QueryRecord) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	rb.items[rb.head] = record
	rb.head = (rb.head + 1) % rb.size
}

func (rb *RingBuffer) GetRecent(n int) []QueryRecord {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	if n > rb.size {
		n = rb.size
	}

	result := make([]QueryRecord, 0, n)
	pos := (rb.head - 1 + rb.size) % rb.size

	for i := 0; i < n; i++ {
		if rb.items[pos].service != "" {
			result = append(result, rb.items[pos])
		}
		pos = (pos - 1 + rb.size) % rb.size
	}

	return result
}
