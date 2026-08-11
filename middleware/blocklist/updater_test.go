package blocklist

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/semihalev/sdns/config"
	"github.com/semihalev/zlog/v2"
	"github.com/stretchr/testify/assert"
)

const (
	testDomain = "www.google.com"
)

func Test_UpdateBlocklists(t *testing.T) {
	logger := zlog.NewStructured()
	logger.SetWriter(zlog.StdoutTerminal())
	logger.SetLevel(zlog.LevelDebug)
	zlog.SetDefault(logger)

	tempDir := filepath.Join(os.TempDir(), "sdns_temp")

	cfg := new(config.Config)
	cfg.BlockListDir = tempDir
	cfg.Whitelist = append(cfg.Whitelist, testDomain)
	cfg.Blocklist = append(cfg.Blocklist, testDomain)

	// Served locally rather than fetched from a third party: the list this
	// used to download could change or disappear, and a blocklist test has
	// no business depending on someone else's repository being up.
	list := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "0.0.0.0 ads.example.\n0.0.0.0 tracker.example.\n")
	}))
	defer list.Close()

	// A source that fails must not take the whole update down with it.
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer broken.Close()

	cfg.BlockLists = []string{list.URL, broken.URL}

	b := New(cfg)

	err := b.readBlocklists()
	assert.NoError(t, err)
}
