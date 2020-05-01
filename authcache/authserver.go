package authcache

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// AuthServer type
type AuthServer struct {
	Host  string
	Rtt   int64
	Count int64
	Mode  Mode
}

// Mode type
type Mode byte

const (
	// IPv4 mode
	IPv4 Mode = 0x1

	// IPv6 mode
	IPv6 Mode = 0x2
)

// NewAuthServer return a server
func NewAuthServer(host string, mode Mode) *AuthServer {
	return &AuthServer{
		Host: host,
		Mode: mode,
	}
}

func (m Mode) String() string {
	switch m {
	case IPv4:
		return "IPv4"
	case IPv6:
		return "IPv6"
	default:
		return "Unknown"
	}
}

func (a *AuthServer) String() string {
	if a.Count == 0 {
		a.Count = 1
	}

	rtt := (time.Duration(a.Rtt) / time.Duration(a.Count)).Round(time.Millisecond)

	health := "UNKNOWN"
	if rtt >= time.Second {
		health = "POOR"
	} else if rtt != 0 {
		health = "GOOD"
	}

	return "host:" + a.Host + " mode:" + a.Mode.String() + " rtt:" + rtt.String() + " health:[" + health + "]"
}

// AuthServers type
type AuthServers struct {
	sync.RWMutex

	called int32
	List   []*AuthServer
}

// TrySort if necessary sort servers by rtt
func (s *AuthServers) TrySort() bool {
	atomic.AddInt32(&s.called, 1)

	if atomic.LoadInt32(&s.called)%20 == 0 {
		s.Lock()
		for _, s := range s.List {
			if s.Count > 0 {
				// average rtt
				s.Rtt = s.Rtt / s.Count
				s.Count = 1
			}
		}
		sort.Slice(s.List, func(i, j int) bool {
			if s.List[i].Rtt == 0 {
				s.List[i].Rtt = 1e3
			}

			if s.List[j].Rtt == 0 {
				s.List[j].Rtt = 1e3
			}

			return s.List[i].Rtt < s.List[j].Rtt
		})
		s.Unlock()
		atomic.StoreInt32(&s.called, 0)

		return true
	}

	return false
}
