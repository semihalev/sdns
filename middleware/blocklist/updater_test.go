package blocklist

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/semihalev/log"
	"github.com/semihalev/sdns/config"
	"github.com/stretchr/testify/assert"
)

const (
	testDomain = "www.google.com"
)

func Test_UpdateBlocklists(t *testing.T) {
	log.Root().SetHandler(log.LvlFilterHandler(0, log.StdoutHandler))

	tempDir := filepath.Join(os.TempDir(), "/sdns_temp")

	cfg := new(config.Config)
	cfg.BlockListDir = tempDir
	cfg.Whitelist = append(cfg.Whitelist, testDomain)
	cfg.Blocklist = append(cfg.Blocklist, testDomain)

	cfg.BlockLists = []string{}
	cfg.BlockLists = append(cfg.BlockLists, "https://raw.githubusercontent.com/quidsup/notrack/master/trackers.txt")
	cfg.BlockLists = append(cfg.BlockLists, "https://test.dev/hosts")

	b := New(cfg)

	err := b.updateBlocklists()
	assert.NoError(t, err)

	err = b.readBlocklists()
	assert.NoError(t, err)
}
