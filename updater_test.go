package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Blocklist(t *testing.T) {
	tempDir := filepath.Join(os.TempDir(), "/sdns_temp")

	Config.Whitelist = append(Config.Whitelist, testDomain)
	Config.Blocklist = append(Config.Blocklist, testDomain)

	Config.BlockLists = []string{}
	Config.BlockLists = append(Config.BlockLists, "https://raw.githubusercontent.com/quidsup/notrack/master/trackers.txt")
	Config.BlockLists = append(Config.BlockLists, "https://test.dev/hosts")

	err := updateBlocklists(tempDir)
	assert.NoError(t, err)

	err = readBlocklists(tempDir)
	assert.NoError(t, err)
}
