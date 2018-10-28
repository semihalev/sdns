package cache

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_TrySort(t *testing.T) {
	s := &AuthServers{
		List: []*AuthServer{NewAuthServer("0.0.0.0:53"), NewAuthServer("0.0.0.1:53")},
	}

	for i := int64(0); i < 100; i++ {
		s.List[0].Count++
		s.List[0].Rtt += (i + 1) % 20
		s.TrySort()
	}

	assert.Equal(t, int64(1), s.List[0].Count)
}
