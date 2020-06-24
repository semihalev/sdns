package waitgroup

import (
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/cache"
	"github.com/stretchr/testify/assert"
)

func Test_WaitGroupWait(t *testing.T) {
	wg := New(5 * time.Second)
	mu := sync.RWMutex{}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("example.com."), dns.TypeA)
	key := cache.Hash(m.Question[0])

	wg.Add(key)

	count := wg.Get(key)
	assert.Equal(t, 1, count)

	key2 := cache.Hash(dns.Question{Name: "none.", Qtype: dns.TypeA, Qclass: dns.ClassINET})

	count = wg.Get(key2)
	assert.Equal(t, 0, count)

	wg.Wait(key2)

	var workers []*string

	for i := 0; i < 5; i++ {
		go func() {
			w := new(string)
			*w = "running"

			mu.Lock()
			workers = append(workers, w)
			mu.Unlock()

			wg.Wait(key)

			mu.Lock()
			*w = "stopped"
			mu.Unlock()
		}()
	}

	time.Sleep(time.Second)

	wg.Done(key)

	time.Sleep(100 * time.Millisecond)

	mu.RLock()
	defer mu.RUnlock()
	for _, w := range workers {
		assert.Equal(t, *w, "stopped")
	}
}
