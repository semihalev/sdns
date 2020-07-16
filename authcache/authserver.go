package authcache

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// AuthServer type
type AuthServer struct {
	// place atomic members at the start to fix alignment for ARM32
	Rtt     int64
	Count   int64
	Addr    string
	Version Version
}

// Version type
type Version byte

const (
	// IPv4 mode
	IPv4 Version = 0x1

	// IPv6 mode
	IPv6 Version = 0x2
)

// NewAuthServer return a new server
func NewAuthServer(addr string, version Version) *AuthServer {
	return &AuthServer{
		Addr:    addr,
		Version: version,
	}
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
	if rn >= int64(time.Second) {
		health = "POOR"
	} else if rn > 0 {
		health = "GOOD"
	} else {
		health = "UNKNOWN"
	}

	rtt := (time.Duration(rn) / time.Duration(count)).Round(time.Millisecond)

	return a.Version.String() + ":" + a.Addr + " rtt:" + rtt.String() + " health:[" + health + "]"
}

// AuthServers type
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

// Sort sort servers by rtt
func Sort(serversList []*AuthServer, called uint64) {
	for _, s := range serversList {
		//clear stats and re-start again
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
