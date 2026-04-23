package authcache

import (
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// AuthServer type.
type AuthServer struct {
	// place atomic members at the start to fix alignment for ARM32
	Rtt     int64
	Count   int64
	Addr    string
	Version Version

	// UDPAddr is Addr pre-parsed as *net.UDPAddr so the upstream
	// exchange path can use net.DialUDP directly instead of going
	// through Dialer.DialContext's string-parsing + dialParallel
	// machinery. Nil only if Addr failed to parse — callers fall
	// back to the string path in that case.
	UDPAddr *net.UDPAddr
}

// Version type.
type Version byte

const (
	// IPv4 mode.
	IPv4 Version = 0x1

	// IPv6 mode.
	IPv6 Version = 0x2
)

// NewAuthServer return a new server. addr is expected to be an
// "IP:port" pair — the IP is parsed once here so upstream exchanges
// can skip Go's DialContext address-resolution path.
func NewAuthServer(addr string, version Version) *AuthServer {
	s := &AuthServer{
		Addr:    addr,
		Version: version,
	}
	if ua, err := net.ResolveUDPAddr("udp", addr); err == nil {
		s.UDPAddr = ua
	}
	return s
}

func (v Version) String() string {
	switch v {
	case IPv4:
		return "IPv4"
	case IPv6:
		return "IPv6"
	default:
		return "Unknown"
	}
}

func (a *AuthServer) String() string {
	count := atomic.LoadInt64(&a.Count)
	rn := atomic.LoadInt64(&a.Rtt)

	if count == 0 {
		count = 1
	}

	var health string
	switch {
	case rn >= int64(time.Second):
		health = "POOR"
	case rn > 0:
		health = "GOOD"
	default:
		health = "UNKNOWN"
	}

	rtt := (time.Duration(rn) / time.Duration(count)).Round(time.Millisecond)

	return a.Version.String() + ":" + a.Addr + " rtt:" + rtt.String() + " health:[" + health + "]"
}

// AuthServers type.
type AuthServers struct {
	sync.RWMutex
	// place atomic members at the start to fix alignment for ARM32
	Called     uint64
	ErrorCount uint32

	Zone string

	List []*AuthServer
	Nss  []string

	CheckingDisable bool
	Checked         bool
}

// Sort sort servers by rtt.
func Sort(serversList []*AuthServer, called uint64) {
	for _, s := range serversList {
		// clear stats and re-start again
		if called%1e3 == 0 {
			atomic.StoreInt64(&s.Rtt, 0)
			atomic.StoreInt64(&s.Count, 0)

			continue
		}

		rtt := atomic.LoadInt64(&s.Rtt)
		count := atomic.LoadInt64(&s.Count)

		if count > 0 {
			// average rtt
			atomic.StoreInt64(&s.Rtt, rtt/count)
			atomic.StoreInt64(&s.Count, 1)
		}
	}
	sort.Slice(serversList, func(i, j int) bool {
		return atomic.LoadInt64(&serversList[i].Rtt) < atomic.LoadInt64(&serversList[j].Rtt)
	})
}
