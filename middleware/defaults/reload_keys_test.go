package defaults

import (
	"slices"
	"testing"

	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/accesslist"
	"github.com/semihalev/sdns/middleware/blocklist"
	"github.com/semihalev/sdns/middleware/ratelimit"
	"github.com/semihalev/sdns/middleware/rpz"
	"github.com/semihalev/sdns/middleware/views"
)

// The keys a reload applies live, as reviewed. A key is safe to apply live
// only when the handler declaring it is the only thing that reads it; a
// key read anywhere else as well must stay restart-only, or a reload would
// leave the two readers disagreeing. Changing this list means checking
// every reader of the key. The test pins keys, not readers: a new reader of
// a listed key elsewhere would not fail it.
var reviewedLiveKeys = []string{
	"accesslist",
	"blocklist",
	"clientratelimit",
	"rpz.mode",
	"views",
	"whitelist",
}

func TestReloadKeysAreTheReviewedOnes(t *testing.T) {
	var keys []string
	for _, h := range []middleware.Reloader{
		&accesslist.List{},
		&blocklist.BlockList{},
		&ratelimit.RateLimit{},
		&rpz.RPZ{},
		&views.Views{},
	} {
		keys = append(keys, h.ReloadKeys()...)
	}
	slices.Sort(keys)
	if !slices.Equal(keys, reviewedLiveKeys) {
		t.Fatalf("live keys %v, reviewed %v", keys, reviewedLiveKeys)
	}
}
