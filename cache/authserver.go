package cache

import (
	"sync"
	"time"
)

// AuthServer type
type AuthServer struct {
	Host string
	RTT  time.Duration
}

// NewAuthServer return a server
func NewAuthServer(host string) *AuthServer {
	return &AuthServer{
		Host: host,
	}
}

func (a *AuthServer) String() string {
	return "host:" + a.Host + " " + "rtt:" + a.RTT.String()
}

// AuthServers type
type AuthServers struct {
	sync.RWMutex

	List []*AuthServer
}
