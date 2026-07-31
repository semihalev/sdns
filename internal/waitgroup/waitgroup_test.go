package waitgroup

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_WaitGroupWait(t *testing.T) {
	wg := New(5 * time.Second)
	mu := sync.RWMutex{}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("example.com."), dns.TypeA)
	key := cache.Key(m.Question[0])

	wg.Add(key)

	count := wg.Get(key)
	assert.Equal(t, 1, count)

	key2 := cache.Key(dns.Question{Name: "none.", Qtype: dns.TypeA, Qclass: dns.ClassINET})

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
	require.Nil(t, wait, "first Join must return nil (leader)")

	// Followers.
	const followers = 3
	var woken atomic.Int32
	done := make(chan struct{}, followers)
	for range followers {
		go func() {
			w := wg.Join(key)
			require.NotNil(t, w, "subsequent Join must return a channel (follower)")
			<-w
			woken.Add(1)
			done <- struct{}{}
		}()
	}

	// Give followers time to block on the channel before the leader
	// calls Done — that's the case the regression would mishandle.
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, int32(0), woken.Load(), "followers must wait for leader's Done")

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
	assert.Equal(t, int32(followers), woken.Load())
}

func Test_RegroupPinsLateFollowersToOneNextGeneration(t *testing.T) {
	wg := New(5 * time.Second)
	key := cache.Key(dns.Question{Name: "regroup.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET})

	first, leader := wg.JoinGeneration(key)
	require.True(t, leader)
	follower, leader := wg.JoinGeneration(key)
	require.False(t, leader)
	require.Same(t, first, follower)
	wg.DoneGeneration(key, first)
	<-first.Done()

	second, leader := wg.Regroup(key, first)
	require.True(t, leader)
	wg.DoneGeneration(key, second)
	<-second.Done()

	// The next generation has already completed, but a late member of the
	// first cohort must still observe that exact token instead of becoming a
	// third leader.
	late, leader := wg.Regroup(key, follower)
	require.False(t, leader)
	require.Same(t, second, late)
}

func Test_DoneGenerationCannotDeleteNewerRegroup(t *testing.T) {
	wg := New(5 * time.Second)
	key := cache.Key(dns.Question{Name: "stale.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET})

	first, leader := wg.JoinGeneration(key)
	require.True(t, leader)
	wg.DoneGeneration(key, first)
	<-first.Done()

	second, leader := wg.Regroup(key, first)
	require.True(t, leader)

	// The abandoned first leader finally returns. Its token-specific Done
	// must not erase the current second generation.
	wg.DoneGeneration(key, first)
	current, leader := wg.JoinGeneration(key)
	require.False(t, leader)
	require.Same(t, second, current)

	wg.DoneGeneration(key, second)
}

func Test_TimedOutGenerationRemainsTombstoneUntilLeaderDone(t *testing.T) {
	wg := New(time.Millisecond)
	key := cache.Key(dns.Question{Name: "timeout.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET})

	first, leader := wg.JoinGeneration(key)
	require.True(t, leader)
	<-first.Done()
	require.ErrorIs(t, first.Err(), context.DeadlineExceeded)

	regrouped, leader := wg.Regroup(key, first)
	require.False(t, leader)
	require.Same(t, first, regrouped)
	current, leader := wg.JoinGeneration(key)
	require.False(t, leader)
	require.Same(t, first, current)

	wg.DoneGeneration(key, first)
	next, leader := wg.JoinGeneration(key)
	require.True(t, leader)
	require.NotSame(t, first, next)
	wg.DoneGeneration(key, next)
}

func Test_ConcurrentRegroupElectsOneSharedLeader(t *testing.T) {
	wg := New(5 * time.Second)
	key := cache.Key(dns.Question{Name: "concurrent.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET})

	first, leader := wg.JoinGeneration(key)
	require.True(t, leader)
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
		} else {
			require.Same(t, next, got.generation)
		}
	}
	require.Equal(t, 1, leaders)
	wg.DoneGeneration(key, next)
}

func Test_JoinAndRegroupRaceAdoptsOneGeneration(t *testing.T) {
	for range 100 {
		wg := New(5 * time.Second)
		key := cache.Key(dns.Question{Name: "adopt.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
		first, leader := wg.JoinGeneration(key)
		require.True(t, leader)
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
		require.Same(t, a.generation, b.generation)
		require.NotEqual(t, a.leader, b.leader)
		wg.DoneGeneration(key, a.generation)
	}
}
