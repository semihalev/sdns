package cache

import (
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// AuthServer type
type AuthServer struct {
	sync.Mutex

	Host  string
	Rtt   time.Duration
	Count int
}

// NewAuthServer return a server
func NewAuthServer(host string) *AuthServer {
	return &AuthServer{
		Host: host,
	}
}

func (a *AuthServer) String() string {
	return "host:" + a.Host + " " + "rtt:" + a.Rtt.String() + "count" + strconv.Itoa(a.Count)
}

// AuthServers type
type AuthServers struct {
	sync.RWMutex

	called int32
	List   []*AuthServer
}

// TrySort if neccessary sort servers by rtt
func (s *AuthServers) TrySort() {
	atomic.AddInt32(&s.called, 1)

	if atomic.LoadInt32(&s.called)%20 == 0 {
		s.Lock()
		for _, s := range s.List {
			if s.Count > 0 {
				// average rtt
				s.Rtt = s.Rtt / time.Duration(s.Count)
				s.Count = 0
			}
		}
		sort.Slice(s.List, func(i, j int) bool {
			return s.List[i].Rtt < s.List[j].Rtt
		})
		s.Unlock()
		atomic.StoreInt32(&s.called, 0)
	}
}
