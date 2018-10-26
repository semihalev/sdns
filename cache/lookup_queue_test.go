package cache

import (
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func Test_lqueueWait(t *testing.T) {
	lqueue := NewLookupQueue()
	mu := sync.RWMutex{}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(testDomain), dns.TypeA)
	key := Hash(m.Question[0])

	lqueue.Add(key)

	ch := lqueue.Get(key)
	assert.NotNil(t, ch)

	key2 := Hash(dns.Question{Name: "none.", Qtype: dns.TypeA, Qclass: dns.ClassINET})

	none := lqueue.Get(key2)
	assert.Nil(t, none)

	lqueue.Wait(key2)

	var workers []*string

	for i := 0; i < 5; i++ {
		go func() {
			w := new(string)
			*w = "running"

			mu.Lock()
			workers = append(workers, w)
			mu.Unlock()

			lqueue.Wait(key)

			mu.Lock()
			*w = "stopped"
			mu.Unlock()
		}()
	}

	time.Sleep(time.Second)

	lqueue.Done(key)

	time.Sleep(100 * time.Millisecond)

	mu.RLock()
	defer mu.RUnlock()
	for _, w := range workers {
		assert.Equal(t, *w, "stopped")
	}
}
