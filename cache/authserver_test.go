package cache

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_TrySort(t *testing.T) {
	s := &AuthServers{
		List: []*AuthServer{NewAuthServer("0.0.0.0:53")},
	}

	for i := 0; i < 100; i++ {
		s.List[0].Count++
		s.List[0].Rtt += time.Duration((i + 1) % 20)
		s.TrySort()
	}

	assert.Equal(t, 1, s.List[0].Count)
}
