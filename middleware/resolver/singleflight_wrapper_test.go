package resolver

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sync/singleflight"
)

type releaseOnDoneContext struct {
	context.Context
	once    sync.Once
	release chan struct{}
}

func (c *releaseOnDoneContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.release) })
	return c.Context.Done()
}

type runOnDoneContext struct {
	context.Context
	once sync.Once
	run  func()
}

func (c *runOnDoneContext) Done() <-chan struct{} {
	c.once.Do(c.run)
	return c.Context.Done()
}

// TestSingleflightWrapperCleanup verifies the cleanup mechanism works.
func TestSingleflightWrapperCleanup(t *testing.T) {
	wrapper := NewSingleflightWrapper()

	// Manually insert a stuck query that started 20 seconds ago
	key := "test-cleanup"
	generation := &singleflightGeneration{started: time.Now().Add(-20 * time.Second)}
	wrapper.current[key] = generation
	wrapper.tracking.Store(key, generation)

	// Also start a real query to verify it affects singleflight
	wrapper.group.DoChan(key, func() (any, error) {
		time.Sleep(30 * time.Second) // This will be forgotten
		return "should-not-complete", nil
	})

	// Verify it's being tracked
	_, exists := wrapper.tracking.Load(key)
	if !exists {
		t.Error("Key should be tracked")
	}

	// Manually trigger cleanup
	wrapper.cleanupStuckQueries()

	// Verify the key was forgotten from tracking
	_, exists = wrapper.tracking.Load(key)
	if exists {
		t.Error("Key should have been cleaned up from tracking")
	}
}

func TestSingleflightWrapperHotFollowersCannotRefreshOrDeleteGeneration(t *testing.T) {
	// Construct without the 30-second background cleanup loop: this test
	// drives cleanup explicitly and ages the published generation in place.
	wrapper := &SingleflightWrapper{
		current: make(map[string]*singleflightGeneration),
	}
	const key = "hot-stuck-key"

	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	var releaseFirstOnce sync.Once
	releaseFirstCall := func() {
		releaseFirstOnce.Do(func() { close(releaseFirst) })
	}
	t.Cleanup(releaseFirstCall)
	firstResult := wrapper.DoChan(key, func() (any, error) {
		close(firstStarted)
		<-releaseFirst
		return "first", nil
	})
	<-firstStarted

	tracked, ok := wrapper.tracking.Load(key)
	if !ok {
		t.Fatal("leader was not tracked after its closure started")
	}
	firstGeneration, ok := tracked.(*singleflightGeneration)
	if !ok {
		t.Fatalf("tracking value = %T, want *singleflightGeneration", tracked)
	}
	firstGeneration.started = time.Now().Add(-20 * time.Second)

	var followerRuns atomic.Int32
	followerResults := make([]<-chan singleflight.Result, 20)
	for i := range followerResults {
		followerResults[i] = wrapper.DoChan(key, func() (any, error) {
			followerRuns.Add(1)
			return "unexpected-follower", nil
		})
	}
	if current, exists := wrapper.tracking.Load(key); !exists || current != firstGeneration {
		t.Fatalf("hot followers replaced leader generation: current=%p first=%p",
			current, firstGeneration)
	}
	if time.Since(firstGeneration.started) < 15*time.Second {
		t.Fatal("hot followers refreshed the stuck-generation start time")
	}

	wrapper.cleanupStuckQueries()
	if _, exists := wrapper.tracking.Load(key); exists {
		t.Fatal("stuck generation remained tracked after cleanup")
	}

	replacementStarted := make(chan struct{})
	releaseReplacement := make(chan struct{})
	var releaseReplacementOnce sync.Once
	releaseReplacementCall := func() {
		releaseReplacementOnce.Do(func() { close(releaseReplacement) })
	}
	t.Cleanup(releaseReplacementCall)
	replacementResult := wrapper.DoChan(key, func() (any, error) {
		close(replacementStarted)
		<-releaseReplacement
		return "replacement", nil
	})
	<-replacementStarted

	replacementTracked, ok := wrapper.tracking.Load(key)
	if !ok || replacementTracked == firstGeneration {
		t.Fatalf("replacement generation = %p, first = %p", replacementTracked, firstGeneration)
	}

	// A stale cleanup candidate must not forget the replacement generation.
	wrapper.retireGeneration(key, firstGeneration)
	if current, exists := wrapper.tracking.Load(key); !exists || current != replacementTracked {
		t.Fatalf("stale cleanup removed replacement: current=%p replacement=%p",
			current, replacementTracked)
	}

	var replacementFollowerRuns atomic.Int32
	replacementFollower := wrapper.DoChan(key, func() (any, error) {
		replacementFollowerRuns.Add(1)
		return "unexpected-replacement-follower", nil
	})

	releaseFirstCall()
	if result := <-firstResult; result.Err != nil || result.Val != "first" {
		t.Fatalf("first result = (%v, %v), want (first, nil)", result.Val, result.Err)
	}
	for i, resultCh := range followerResults {
		result := <-resultCh
		if result.Err != nil || result.Val != "first" {
			t.Fatalf("first-generation follower %d = (%v, %v), want (first, nil)",
				i, result.Val, result.Err)
		}
	}
	if current, exists := wrapper.tracking.Load(key); !exists || current != replacementTracked {
		t.Fatalf("old leader completion removed replacement: current=%p replacement=%p",
			current, replacementTracked)
	}

	releaseReplacementCall()
	if result := <-replacementResult; result.Err != nil || result.Val != "replacement" {
		t.Fatalf("replacement result = (%v, %v), want (replacement, nil)",
			result.Val, result.Err)
	}
	if result := <-replacementFollower; result.Err != nil || result.Val != "replacement" {
		t.Fatalf("replacement follower = (%v, %v), want (replacement, nil)",
			result.Val, result.Err)
	}
	if got := followerRuns.Load(); got != 0 {
		t.Fatalf("first-generation follower closures ran %d times, want 0", got)
	}
	if got := replacementFollowerRuns.Load(); got != 0 {
		t.Fatalf("replacement follower closure ran %d times, want 0", got)
	}
}

// TestTimedDoChan verifies the TimedDoChan method works correctly.
func TestTimedDoChan(t *testing.T) {
	wrapper := NewSingleflightWrapper()

	// Test successful execution
	t.Run("Success", func(t *testing.T) {
		ctx := context.Background()
		result, _, err := wrapper.TimedDoChan(ctx, "test-success", func() (any, error) {
			return "success", nil
		})

		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		if result != "success" {
			t.Errorf("Expected 'success', got %v", result)
		}
	})

	// Test context cancellation
	t.Run("ContextCancel", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())

		// Start a slow query
		done := make(chan struct{})
		go func() {
			_, _, err := wrapper.TimedDoChan(ctx, "test-cancel", func() (any, error) {
				time.Sleep(5 * time.Second)
				return "should-not-complete", nil
			})

			if err != context.Canceled {
				t.Errorf("Expected context.Canceled, got %v", err)
			}
			close(done)
		}()

		// Give it time to start
		time.Sleep(100 * time.Millisecond)

		// Cancel the context
		cancel()

		// Wait for completion
		select {
		case <-done:
			// Success
		case <-time.After(1 * time.Second):
			t.Error("TimedDoChan did not return after context cancellation")
		}
	})

	// Test deduplication
	t.Run("Deduplication", func(t *testing.T) {
		callCount := int32(0)
		var wg sync.WaitGroup

		// Run many concurrent requests for the same key
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()

				ctx := context.Background()
				_, _, err := wrapper.TimedDoChan(ctx, "test-dedup", func() (any, error) {
					atomic.AddInt32(&callCount, 1)
					time.Sleep(100 * time.Millisecond)
					return "result", nil
				})

				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}()
		}

		wg.Wait()

		// Despite many concurrent requests, function should only be called once
		if calls := atomic.LoadInt32(&callCount); calls != 1 {
			t.Errorf("Expected function to be called once, was called %d times", calls)
		}
	})
}

func TestTimedDoChanWithRoleDistinguishesLeaderAndFollower(t *testing.T) {
	wrapper := NewSingleflightWrapper()

	leaderStarted := make(chan struct{})
	releaseLeader := make(chan struct{})
	type result struct {
		value  any
		shared bool
		leader bool
		err    error
	}

	leaderResult := make(chan result, 1)
	go func() {
		value, shared, leader, err := wrapper.TimedDoChanWithRole(
			context.Background(),
			"role-test",
			func() (any, error) {
				close(leaderStarted)
				<-releaseLeader
				return "leader-value", nil
			},
		)
		leaderResult <- result{value: value, shared: shared, leader: leader, err: err}
	}()
	<-leaderStarted

	var followerRuns atomic.Int32
	followerCtx := &releaseOnDoneContext{
		Context: context.Background(),
		release: releaseLeader,
	}
	value, shared, leader, err := wrapper.TimedDoChanWithRole(
		followerCtx,
		"role-test",
		func() (any, error) {
			followerRuns.Add(1)
			return "follower-value", nil
		},
	)
	second := result{value: value, shared: shared, leader: leader, err: err}

	first := <-leaderResult
	if first.err != nil || second.err != nil {
		t.Fatalf("leader error = %v, follower error = %v", first.err, second.err)
	}
	if first.value != "leader-value" || second.value != "leader-value" {
		t.Fatalf("values = leader:%v follower:%v, want shared leader-value",
			first.value, second.value)
	}
	if !first.shared || !second.shared {
		t.Fatalf("shared flags = leader:%v follower:%v, want both true",
			first.shared, second.shared)
	}
	if !first.leader || second.leader {
		t.Fatalf("leader flags = first:%v second:%v, want true/false",
			first.leader, second.leader)
	}
	if got := followerRuns.Load(); got != 0 {
		t.Fatalf("follower closure ran %d times, want 0", got)
	}
}

func TestTimedDoChanCanceledFollowerDoesNotForgetLeader(t *testing.T) {
	wrapper := NewSingleflightWrapper()
	testTimeout := time.After(5 * time.Second)

	leaderStarted := make(chan struct{})
	releaseLeader := make(chan struct{})
	var releaseLeaderOnce sync.Once
	closeLeader := func() {
		releaseLeaderOnce.Do(func() { close(releaseLeader) })
	}
	t.Cleanup(closeLeader)
	leaderDone := make(chan error, 1)
	go func() {
		value, _, err := wrapper.TimedDoChan(context.Background(), "cancel-follower", func() (any, error) {
			close(leaderStarted)
			<-releaseLeader
			return "leader-value", nil
		})
		if err == nil && value != "leader-value" {
			err = errors.New("leader received unexpected value")
		}
		leaderDone <- err
	}()
	select {
	case <-leaderStarted:
	case <-testTimeout:
		t.Fatal("timed out waiting for singleflight leader")
	}

	followerBase, cancelFollower := context.WithCancel(context.Background())
	followerJoined := make(chan struct{})
	followerCtx := &releaseOnDoneContext{
		Context: followerBase,
		release: followerJoined,
	}
	followerDone := make(chan error, 1)
	go func() {
		_, _, err := wrapper.TimedDoChan(followerCtx, "cancel-follower", func() (any, error) {
			return "unexpected follower value", nil
		})
		followerDone <- err
	}()
	select {
	case <-followerJoined:
	case <-testTimeout:
		t.Fatal("timed out waiting for follower to join")
	}
	cancelFollower()
	var followerErr error
	select {
	case followerErr = <-followerDone:
	case <-testTimeout:
		t.Fatal("timed out waiting for canceled follower")
	}
	if !errors.Is(followerErr, context.Canceled) {
		t.Fatalf("canceled follower error = %v, want context.Canceled", followerErr)
	}

	var replacementRuns atomic.Int32
	nextCtx := &runOnDoneContext{
		Context: context.Background(),
		run:     closeLeader,
	}
	value, shared, err := wrapper.TimedDoChan(nextCtx, "cancel-follower", func() (any, error) {
		replacementRuns.Add(1)
		return "replacement-value", nil
	})
	if err != nil {
		t.Fatalf("next follower error: %v", err)
	}
	if value != "leader-value" || !shared {
		t.Fatalf("next follower = value:%v shared:%v, want shared leader-value", value, shared)
	}
	if got := replacementRuns.Load(); got != 0 {
		t.Fatalf("replacement closure ran %d times, want 0", got)
	}
	var leaderErr error
	select {
	case leaderErr = <-leaderDone:
	case <-testTimeout:
		t.Fatal("timed out waiting for original leader")
	}
	if leaderErr != nil {
		t.Fatalf("leader error: %v", leaderErr)
	}
}

// TestCleanupLoop verifies that stuck queries are cleaned up periodically.
func TestCleanupLoop(t *testing.T) {
	// This test would normally take 30+ seconds due to the cleanup ticker
	// For unit tests, we'll just verify the mechanism works by calling it directly
	wrapper := NewSingleflightWrapper()

	// Add multiple stuck queries
	for i := 0; i < 5; i++ {
		key := string(rune('a' + i))
		generation := &singleflightGeneration{
			started: time.Now().Add(-20 * time.Second),
		}
		wrapper.current[key] = generation
		wrapper.tracking.Store(key, generation)
	}

	// Run cleanup
	wrapper.cleanupStuckQueries()

	// Verify all were cleaned up
	count := 0
	wrapper.tracking.Range(func(key, value any) bool {
		count++
		return true
	})

	if count != 0 {
		t.Errorf("Expected all stuck queries to be cleaned up, but %d remain", count)
	}
}
