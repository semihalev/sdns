package authcache

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_TrySort(t *testing.T) {
	s := &AuthServers{
		List: []*AuthServer{},
	}

	for i := 0; i < 10; i++ {
		s.List = append(s.List, NewAuthServer(fmt.Sprintf("0.0.0.%d:53", i), IPv4))
		s.List = append(s.List, NewAuthServer(fmt.Sprintf("[::%d]:53", i), IPv6))
	}

	r := rand.New(rand.NewSource(time.Now().UnixNano())) //nolint:gosec // G404 - test file, not used for crypto
	for i := 0; i < 2000; i++ {
		for j := range s.List {
			s.List[j].Count++
			s.List[j].Rtt += (time.Duration(r.Intn(2000-0)+0) * time.Millisecond).Nanoseconds()
			Sort(s.List, uint64(i))
		}
	}

	assert.Equal(t, int64(1), s.List[0].Count)
}

func Test_VersionString(t *testing.T) {
	assert.Equal(t, "IPv4", IPv4.String())
	assert.Equal(t, "IPv6", IPv6.String())
	assert.Equal(t, "Unknown", Version(0).String())
	assert.Equal(t, "Unknown", Version(99).String())
}

func Test_AuthServerString(t *testing.T) {
	// Test UNKNOWN health (Rtt <= 0)
	s := NewAuthServer("1.2.3.4:53", IPv4)
	str := s.String()
	assert.Contains(t, str, "IPv4")
	assert.Contains(t, str, "1.2.3.4:53")
	assert.Contains(t, str, "UNKNOWN")

	// Test GOOD health (0 < Rtt < 1 second)
	s.Rtt = int64(100 * time.Millisecond)
	s.Count = 1
	str = s.String()
	assert.Contains(t, str, "GOOD")

	// Test POOR health (Rtt >= 1 second)
	s.Rtt = int64(2 * time.Second)
	s.Count = 1
	str = s.String()
	assert.Contains(t, str, "POOR")
}
