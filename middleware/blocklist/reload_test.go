package blocklist

import (
	"os"
	"slices"
	"sync"
	"testing"

	"github.com/semihalev/sdns/config"
)

// A reload adds the configured blocks and replaces the whitelist on
// commit, while queries keep arriving. A block the file no longer lists
// stays, since the API may have saved it too, and nothing is written to
// disk.
func TestReloadAppliesTheConfiguredListsOnCommit(t *testing.T) {
	dir := t.TempDir()
	b := New(&config.Config{
		BlockListDir: dir,
		Blocklist:    []string{"old.example."},
		Whitelist:    []string{"kept-open.example."},
	})
	if !slices.Equal(b.ReloadKeys(), []string{"blocklist", "whitelist"}) {
		t.Fatalf("keys %v", b.ReloadKeys())
	}
	block := func(name string) bool {
		b.mu.Lock()
		defer b.mu.Unlock()
		return b.setLocked(name)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
				b.Exists("new.example.")
			}
		}
	})

	commit, err := b.PrepareReload(&config.Config{
		BlockListDir: dir,
		Blocklist:    []string{"new.example.", "open.example."},
		Whitelist:    []string{"open.example."},
	})
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if b.Exists("new.example.") {
		t.Fatal("prepare changed the lists in use")
	}
	commit()
	close(stop)
	wg.Wait()

	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Fatalf("the reload wrote to the blocklist directory: %v %v", entries, err)
	}
	if !b.Exists("new.example.") {
		t.Fatal("an added block is not in use after commit")
	}
	if !b.Exists("old.example.") {
		t.Fatal("a block the file dropped was removed")
	}
	// The whitelist is committed first, so a name both lists carry is
	// exempt rather than blocked.
	if b.Exists("open.example.") {
		t.Fatal("the new whitelist does not exempt its name")
	}
	if !block("kept-open.example.") || !b.Exists("kept-open.example.") {
		t.Fatal("a name the new whitelist dropped still cannot be blocked")
	}
}
