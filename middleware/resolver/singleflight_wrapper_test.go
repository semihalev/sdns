package resolver

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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

// TestSingleflightWrapperCleanup verifies the cleanup mechanism works.
func TestSingleflightWrapperCleanup(t *testing.T) {
	wrapper := NewSingleflightWrapper()

	// Manually insert a stuck query that started 20 seconds ago
	key := "test-cleanup"
	oldStartTime := time.Now().Add(-20 * time.Second)
	wrapper.tracking.Store(key, oldStartTime)

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

// TestCleanupLoop verifies that stuck queries are cleaned up periodically.
func TestCleanupLoop(t *testing.T) {
	// This test would normally take 30+ seconds due to the cleanup ticker
	// For unit tests, we'll just verify the mechanism works by calling it directly
	wrapper := NewSingleflightWrapper()

	// Add multiple stuck queries
	for i := 0; i < 5; i++ {
		key := string(rune('a' + i))
		wrapper.tracking.Store(key, time.Now().Add(-20*time.Second)) // Pretend they started 20s ago
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
