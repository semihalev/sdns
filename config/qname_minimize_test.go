package config

import "testing"

// TestQnameMinimizeParams covers the shapes a config can arrive in: the
// deprecated key alone, the current keys, both, and neither. The folding lives
// in one pure function so a Config built in code resolves exactly as a loaded
// file does.
func TestQnameMinimizeParams(t *testing.T) {
	cases := []struct {
		name     string
		cfg      Config
		maxCount int
		oneLabel int
	}{
		{
			// Every deployed config is this one until its operator moves over.
			name:     "deprecated key alone",
			cfg:      Config{QnameMinLevel: 3},
			maxCount: 3,
			oneLabel: 3, // no room for the suggested 4
		},
		{
			name:     "current key alone takes the suggested one-label count",
			cfg:      Config{QnameMaxMinimizeCount: new(10)},
			maxCount: 10,
			oneLabel: 4,
		},
		{
			name:     "both current keys are honoured",
			cfg:      Config{QnameMaxMinimizeCount: new(10), QnameMinimizeOneLabel: 6},
			maxCount: 10,
			oneLabel: 6,
		},
		{
			name:     "current key wins over the deprecated one",
			cfg:      Config{QnameMinLevel: 3, QnameMaxMinimizeCount: new(10)},
			maxCount: 10,
			oneLabel: 4,
		},
		{
			// The case that demands the pointer: an operator switching
			// minimization off while the deprecated key is still in the file.
			// Treating the written zero as "unset" would silently re-enable it
			// from qname_min_level.
			name:     "explicit zero disables even with the deprecated key present",
			cfg:      Config{QnameMinLevel: 3, QnameMaxMinimizeCount: new(0)},
			maxCount: 0,
			oneLabel: 0,
		},
		{
			name:     "neither key disables minimization",
			cfg:      Config{},
			maxCount: 0,
			oneLabel: 0,
		},
		{
			name:     "negative counts disable rather than underflow",
			cfg:      Config{QnameMaxMinimizeCount: new(-1), QnameMinimizeOneLabel: -1},
			maxCount: 0,
			oneLabel: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			maxCount, oneLabel := tc.cfg.QnameMinimizeParams()
			if maxCount != tc.maxCount || oneLabel != tc.oneLabel {
				t.Fatalf("params = (%d, %d), want (%d, %d)", maxCount, oneLabel, tc.maxCount, tc.oneLabel)
			}

			// Load normalizes onto the same fields it reads, so settling twice
			// must not drift.
			tc.cfg.normalizeQnameMinimize()
			again, againOne := tc.cfg.QnameMinimizeParams()
			if again != maxCount || againOne != oneLabel {
				t.Fatalf("after normalize params = (%d, %d), want (%d, %d)", again, againOne, maxCount, oneLabel)
			}
		})
	}
}
