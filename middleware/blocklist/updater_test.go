package blocklist

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/semihalev/sdns/config"
	"github.com/semihalev/zlog/v2"
)

const (
	testDomain = "www.google.com"
)

func Test_UpdateBlocklists(t *testing.T) {
	logger := zlog.NewStructured()
	logger.SetWriter(zlog.StdoutTerminal())
	logger.SetLevel(zlog.LevelDebug)
	zlog.SetDefault(logger)

	// A directory of this test's own. The shared one under TempDir kept
	// whatever earlier runs had downloaded, so this passed on a machine that
	// already had lists lying about and proved nothing on a clean one.
	cfg := new(config.Config)
	cfg.BlockListDir = t.TempDir()
	cfg.Whitelist = append(cfg.Whitelist, testDomain)
	cfg.Blocklist = append(cfg.Blocklist, testDomain)

	// Served locally rather than fetched from a third party: the list this
	// used to download could change or disappear, and a blocklist test has
	// no business depending on someone else's repository being up.
	var served, failed atomic.Int32
	list := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		served.Add(1)
		_, _ = io.WriteString(w, "0.0.0.0 ads.example.\n0.0.0.0 tracker.example.\n")
	}))
	defer list.Close()

	// A source that fails must not take the whole update down with it.
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		failed.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer broken.Close()

	cfg.BlockLists = []string{list.URL, broken.URL}

	b := New(cfg)

	// New only schedules a refresh for later, so fetch here: without this
	// the test reads an empty directory and asserts that reading nothing
	// succeeds. The counters prove both sources were actually contacted.
	b.fetchBlocklist()
	if got := served.Load(); got != 1 {
		t.Fatalf("the working list was requested %d times, want once", got)
	}
	if got := failed.Load(); got != 1 {
		t.Fatalf("the failing list was requested %d times, want once", got)
	}

	if err := b.readBlocklists(); err != nil {
		t.Fatalf("read blocklists: %v", err)
	}

	// The entries from the source that worked are in place, and the source
	// that failed did not prevent them from being loaded.
	for _, blocked := range []string{"ads.example.", "tracker.example."} {
		if !b.Exists(blocked) {
			t.Errorf("%s was served by the working list but is not blocked", blocked)
		}
	}
}

// TestFileNameForHost pins that a host is turned into something every
// filesystem will accept. A list configured with an explicit port used to
// produce a name Windows refuses, and the download was dropped with only a
// log line to show for it.
func TestFileNameForHost(t *testing.T) {
	hosts := []string{
		"lists.example",
		"lists.example:8080",
		// Sanitising alone would fold this onto the one above, and two
		// concurrent downloads would then truncate each other's file.
		"lists.example_8080",
		"127.0.0.1:51542",
		"[::1]:53",
		"con",
		strings.Repeat("very-long-host.", 20) + "example",
	}

	seen := make(map[string]string, len(hosts))
	for _, host := range hosts {
		name := fileNameForHost(host)

		if strings.ContainsAny(name, `:/\<>"|?*`) {
			t.Errorf("fileNameForHost(%q) = %q, which not every filesystem accepts", host, name)
		}
		if len(name) > 96 {
			t.Errorf("fileNameForHost(%q) is %d characters", host, len(name))
		}
		if other, clash := seen[name]; clash {
			t.Errorf("%q and %q both map to %q", other, host, name)
		}
		seen[name] = host
	}
}
