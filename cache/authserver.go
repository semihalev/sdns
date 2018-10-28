package cache

import (
	"sort"
	"sync"
	"time"
)

// AuthServer type
type AuthServer struct {
	Host string
	Rtt  time.Duration
}

// NewAuthServer return a server
func NewAuthServer(host string) *AuthServer {
	return &AuthServer{
		Host: host,
	}
}

func (a *AuthServer) String() string {
	return "host:" + a.Host + " " + "rtt:" + a.Rtt.String()
}

// AuthServers type
type AuthServers struct {
	sync.RWMutex

	used int
	List []*AuthServer
}

// TrySort servers sort by Rtt if neccessary
func (s *AuthServers) TrySort() {
	s.Lock()
	defer s.Unlock()

	s.used++
	if s.used%5 == 0 {
		sort.Slice(s.List, func(i, j int) bool {
			return s.List[i].Rtt/time.Duration(s.used) < s.List[j].Rtt/time.Duration(s.used)
		})
		s.used = 0
	}
}
