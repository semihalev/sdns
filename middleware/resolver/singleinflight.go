// Copyright 2013 The Go Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Adapted for resolver package usage by Semih Alev.

package resolver

import (
	"sync"

	"github.com/miekg/dns"
)

// call is an in-flight or completed singleflight.Do call
type call struct {
	wg   sync.WaitGroup
	val  *dns.Msg
	err  error
	dups int
}

// singleflight represents a class of work and forms a namespace in
// which units of work can be executed with duplicate suppression.
type singleflight struct {
	sync.RWMutex                  // protects m
	m            map[uint64]*call // lazily initialized
}

// Do executes and returns the results of the given function, making
// sure that only one execution is in-flight for a given key at a
// time. If a duplicate comes in, the duplicate caller waits for the
// original to complete and receives the same results.
// The return value shared indicates whether v was given to multiple callers.
func (g *singleflight) Do(key uint64, fn func() (*dns.Msg, error)) (v *dns.Msg, shared bool, err error) {
	g.Lock()
	if g.m == nil {
		g.m = make(map[uint64]*call)
	}
	if c, ok := g.m[key]; ok {
		c.dups++
		g.Unlock()
		c.wg.Wait()
		return c.val, true, c.err
	}
	c := new(call)
	c.wg.Add(1)
	g.m[key] = c
	g.Unlock()

	c.val, c.err = fn()
	c.wg.Done()

	g.Lock()
	delete(g.m, key)
	g.Unlock()

	return c.val, c.dups > 0, c.err
}

func (g *singleflight) Exists(key uint64) bool {
	g.RLock()
	defer g.RUnlock()

	if _, ok := g.m[key]; ok {
		return true
	}

	return false
}
