package cache

import "time"

// AuthServer type
type AuthServer struct {
	Host string
	RTT  time.Duration
}

// NewAuthServer return a server
func NewAuthServer(host string) *AuthServer {
	return &AuthServer{
		Host: host,
		RTT:  time.Hour, //default untrusted rtt
	}
}

func (a *AuthServer) String() string {
	return "host:" + a.Host + " " + "rtt:" + a.RTT.String()
}
