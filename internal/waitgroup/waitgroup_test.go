package waitgroup

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/cache"
)

func Test_WaitGroupWait(t *testing.T) {
	wg := New(5 * time.Second)
	mu := sync.RWMutex{}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("example.com."), dns.TypeA)
	key := cache.Key(m.Question[0])

	wg.Add(key)

	count := wg.Get(key)
	if !reflect.DeepEqual(1, count) {
		t.Errorf("count = %v, want %v", count, 1)
	}

	key2 := cache.Key(dns.Question{Name: "none.", Qtype: dns.TypeA, Qclass: dns.ClassINET})

	count = wg.Get(key2)
	if !reflect.DeepEqual(0, count) {
		t.Errorf("count = %v, want %v", count, 0)
	}

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
		if !reflect.DeepEqual(*w, "stopped") {
			t.Errorf("'stopped' = %v, want %v", "stopped", *w)
		}
	}
}

// Test_JoinLeaderWakesFollowers guards against a regression where
// Join incremented the dup counter for followers. With that bug, the
// leader's Done would decrement from 2 to 1 instead of cancelling the
// shared context, so followers stayed blocked on the done-channel
// until the WaitGroup's timeout fired. Followers must wake as soon
// as the leader calls Done.
func Test_JoinLeaderWakesFollowers(t *testing.T) {
	wg := New(5 * time.Second)
	key := cache.Key(dns.Question{Name: "leader.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET})

	// Leader.
	wait := wg.Join(key)
	if wait != nil {
		t.Fatalf("%s: wait = %v, want nil", "first Join must return nil (leader)", wait)
	}

	// Followers.
	const followers = 3
	var woken atomic.Int32
	done := make(chan struct{}, followers)
	for range followers {
		go func() {
			w := wg.Join(key)
			if w == nil {
				// Errorf, not Fatalf: FailNow must not run off the test
				// goroutine, and the collector below still needs its done.
				t.Errorf("subsequent Join must return a channel (follower)")
				done <- struct{}{}
				return
			}
			<-w
			woken.Add(1)
			done <- struct{}{}
		}()
	}

	// Give followers time to block on the channel before the leader
	// calls Done, that's the case the regression would mishandle.
	time.Sleep(50 * time.Millisecond)
	if !reflect.DeepEqual(int32(0), woken.Load()) {
		t.Errorf("%s: woken.Load() = %v, want %v", "followers must wait for leader's Done", woken.Load(), int32(0))
	}

	// Leader finishes. All followers should wake well before the
	// 5s wait timeout would expire.
	start := time.Now()
	wg.Done(key)

	for range followers {
		select {
		case <-done:
		case <-time.After(500 * time.Millisecond):
			t.Fatalf("follower still blocked %v after leader Done", time.Since(start))
		}
	}
	if !reflect.DeepEqual(int32(followers), woken.Load()) {
		t.Errorf("woken.Load() = %v, want %v", woken.Load(), int32(followers))
	}
}

func Test_RegroupPinsLateFollowersToOneNextGeneration(t *testing.T) {
	wg := New(5 * time.Second)
	key := cache.Key(dns.Question{Name: "regroup.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET})

	first, leader := wg.JoinGeneration(key)
	if !(leader) {
		t.Fatalf("leader is false")
	}
	follower, leader := wg.JoinGeneration(key)
	if leader {
		t.Fatalf("leader is true")
	}
	if first != follower {
		t.Fatalf("%p and %p are not the same pointer", first, follower)
	}
	wg.DoneGeneration(key, first)
	<-first.Done()

	second, leader := wg.Regroup(key, first)
	if !(leader) {
		t.Fatalf("leader is false")
	}
	wg.DoneGeneration(key, second)
	<-second.Done()

	// The next generation has already completed, but a late member of the
	// first cohort must still observe that exact token instead of becoming a
	// third leader.
	late, leader := wg.Regroup(key, follower)
	if leader {
		t.Fatalf("leader is true")
	}
	if second != late {
		t.Fatalf("%p and %p are not the same pointer", second, late)
	}
}

func Test_DoneGenerationCannotDeleteNewerRegroup(t *testing.T) {
	wg := New(5 * time.Second)
	key := cache.Key(dns.Question{Name: "stale.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET})

	first, leader := wg.JoinGeneration(key)
	if !(leader) {
		t.Fatalf("leader is false")
	}
	wg.DoneGeneration(key, first)
	<-first.Done()

	second, leader := wg.Regroup(key, first)
	if !(leader) {
		t.Fatalf("leader is false")
	}

	// The abandoned first leader finally returns. Its token-specific Done
	// must not erase the current second generation.
	wg.DoneGeneration(key, first)
	current, leader := wg.JoinGeneration(key)
	if leader {
		t.Fatalf("leader is true")
	}
	if second != current {
		t.Fatalf("%p and %p are not the same pointer", second, current)
	}

	wg.DoneGeneration(key, second)
}

func Test_TimedOutGenerationRemainsTombstoneUntilLeaderDone(t *testing.T) {
	wg := New(time.Millisecond)
	key := cache.Key(dns.Question{Name: "timeout.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET})

	first, leader := wg.JoinGeneration(key)
	if !(leader) {
		t.Fatalf("leader is false")
	}
	<-first.Done()
	if !errors.Is(first.Err(), context.DeadlineExceeded) {
		t.Fatalf("error = %v, want %v", first.Err(), context.DeadlineExceeded)
	}

	regrouped, leader := wg.Regroup(key, first)
	if leader {
		t.Fatalf("leader is true")
	}
	if first != regrouped {
		t.Fatalf("%p and %p are not the same pointer", first, regrouped)
	}
	current, leader := wg.JoinGeneration(key)
	if leader {
		t.Fatalf("leader is true")
	}
	if first != current {
		t.Fatalf("%p and %p are not the same pointer", first, current)
	}

	wg.DoneGeneration(key, first)
	next, leader := wg.JoinGeneration(key)
	if !(leader) {
		t.Fatalf("leader is false")
	}
	if first == next {
		t.Fatalf("%p is the same pointer", first)
	}
	wg.DoneGeneration(key, next)
}

func Test_ConcurrentRegroupElectsOneSharedLeader(t *testing.T) {
	wg := New(5 * time.Second)
	key := cache.Key(dns.Question{Name: "concurrent.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET})

	first, leader := wg.JoinGeneration(key)
	if !(leader) {
		t.Fatalf("leader is false")
	}
	wg.DoneGeneration(key, first)
	<-first.Done()

	const followers = 32
	start := make(chan struct{})
	type result struct {
		generation *Generation
		leader     bool
	}
	results := make(chan result, followers)
	for range followers {
		go func() {
			<-start
			generation, elected := wg.Regroup(key, first)
			results <- result{generation: generation, leader: elected}
		}()
	}
	close(start)

	var (
		next    *Generation
		leaders int
	)
	for range followers {
		got := <-results
		if got.leader {
			leaders++
		}
		if next == nil {
			next = got.generation
		} else if next != got.generation {
			t.Fatalf("%p and %p are not the same pointer", next, got.generation)
		}
	}
	if !reflect.DeepEqual(1, leaders) {
		t.Fatalf("leaders = %v, want %v", leaders, 1)
	}
	wg.DoneGeneration(key, next)
}

func Test_JoinAndRegroupRaceAdoptsOneGeneration(t *testing.T) {
	for range 100 {
		wg := New(5 * time.Second)
		key := cache.Key(dns.Question{Name: "adopt.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
		first, leader := wg.JoinGeneration(key)
		if !(leader) {
			t.Fatalf("leader is false")
		}
		wg.DoneGeneration(key, first)
		<-first.Done()

		start := make(chan struct{})
		type result struct {
			generation *Generation
			leader     bool
		}
		results := make(chan result, 2)
		go func() {
			<-start
			generation, elected := wg.JoinGeneration(key)
			results <- result{generation: generation, leader: elected}
		}()
		go func() {
			<-start
			generation, elected := wg.Regroup(key, first)
			results <- result{generation: generation, leader: elected}
		}()
		close(start)

		a := <-results
		b := <-results
		if a.generation != b.generation {
			t.Fatalf("%p and %p are not the same pointer", a.generation, b.generation)
		}
		if reflect.DeepEqual(a.leader, b.leader) {
			t.Fatalf("b.leader = %v, want a different value", b.leader)
		}
		wg.DoneGeneration(key, a.generation)
	}
}
