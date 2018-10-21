package main

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

	key := keyGen(dns.Question{Name: "google.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET})

	lqueue.Add(key)

	ch := lqueue.Get(key)
	assert.NotNil(t, ch)

	none := lqueue.Get("none")
	assert.Nil(t, none)

	lqueue.Wait("none")

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
