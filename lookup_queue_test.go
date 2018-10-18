package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_lqueueWait(t *testing.T) {
	lqueue := NewLookupQueue()

	key := keyGen(Question{"google.com", "A", "IN"})

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
			workers = append(workers, w)
			lqueue.Wait(key)
			*w = "stopped"
		}()
	}

	time.Sleep(time.Second)

	lqueue.Done(key)

	time.Sleep(100 * time.Millisecond)

	for _, w := range workers {
		assert.Equal(t, *w, "stopped")
	}
}
