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

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < 2000; i++ {
		for j := range s.List {
			s.List[j].Count++
			s.List[j].Rtt += (time.Duration(r.Intn(2000-0)+0) * time.Millisecond).Nanoseconds()
			Sort(s.List, uint64(i))
		}
	}

	assert.Equal(t, int64(1), s.List[0].Count)
}
