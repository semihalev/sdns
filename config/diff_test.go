package config

import (
	"slices"
	"testing"
)

func parseWith(t *testing.T, extra string) *Config {
	t.Helper()
	path, _ := writeMinimal(t, extra)
	cfg, err := Parse(path, nil)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return cfg
}

// The same file read twice differs in nothing, whatever the defaults
// settled on it.
func TestChangedKeysOfTheSameFileIsEmpty(t *testing.T) {
	path, _ := writeMinimal(t, "accesslist = [\"192.0.2.0/24\"]\n[[views]]\nzone = \"office\"\nnetworks = [\"192.0.2.0/24\"]\nanswers = [\"printer.local. 60 IN A 192.0.2.10\"]\n")
	a, err := Parse(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if keys := ChangedKeys(a, b); len(keys) != 0 {
		t.Fatalf("same file changed %v", keys)
	}
}

// Keys are named as the file names them: dotted inside a table, and an
// array of tables or a list changes as a whole under its own key.
func TestChangedKeysNamesWhatTheFileSays(t *testing.T) {
	old := parseWith(t, "loglevel = \"info\"\n[rpz]\nmode = \"shadow\"\n")
	next := parseWith(t, "loglevel = \"debug\"\naccesslist = [\"192.0.2.0/24\"]\n[rpz]\nmode = \"enforce\"\n[[views]]\nzone = \"office\"\nnetworks = [\"192.0.2.0/24\"]\nanswers = [\"printer.local. 60 IN A 192.0.2.10\"]\n")
	next.Directory = old.Directory
	next.BlockListDir = old.BlockListDir

	got := ChangedKeys(old, next)
	want := []string{"accesslist", "loglevel", "rpz.mode", "views"}
	if !slices.Equal(got, want) {
		t.Fatalf("changed = %v, want %v", got, want)
	}
}

// Writing a default out in full changes nothing: rfc8198 = true is what
// leaving it out means, and the ignored version line is no setting.
func TestChangedKeysComparesMeaning(t *testing.T) {
	old := parseWith(t, "")
	next := parseWith(t, "rfc8198 = true\nrfc9520 = true\nloglevel = \"info\"\nversion = \"1.9.0\"\n")
	next.Directory = old.Directory
	next.BlockListDir = old.BlockListDir
	if keys := ChangedKeys(old, next); len(keys) != 0 {
		t.Fatalf("writing out the defaults changed %v", keys)
	}

	off := parseWith(t, "rfc8198 = false\n")
	off.Directory = old.Directory
	off.BlockListDir = old.BlockListDir
	if keys := ChangedKeys(old, off); !slices.Equal(keys, []string{"rfc8198"}) {
		t.Fatalf("turning rfc8198 off changed %v, want [rfc8198]", keys)
	}
}
