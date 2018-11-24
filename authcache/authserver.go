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
}

// NewAuthServer return a server
func NewAuthServer(host string) *AuthServer {
	return &AuthServer{
		Host: host,
	}
}

func (a *AuthServer) String() string {
	if a.Count == 0 {
		a.Count = 1
	}

	return "host:" + a.Host + " rtt:" + (time.Duration(a.Rtt) / time.Duration(a.Count)).Round(time.Millisecond).String()
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
			return s.List[i].Rtt < s.List[j].Rtt
		})
		s.Unlock()
		atomic.StoreInt32(&s.called, 0)

		return true
	}

	return false
}
