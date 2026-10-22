package middleware

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/semihalev/sdns/config"
	"github.com/semihalev/zlog/v2"
)

// reloadable is a handler that owns keys and records what a reload asked
// of it.
type reloadable struct {
	name     string
	keys     []string
	fail     error
	prepared []*config.Config
	commits  *[]string
}

func (h *reloadable) Name() string                          { return h.name }
func (h *reloadable) ServeDNS(_ context.Context, ch *Chain) { ch.Next(context.Background()) }
func (h *reloadable) ReloadKeys() []string                  { return h.keys }
func (h *reloadable) PrepareReload(cfg *config.Config) (func(), error) {
	h.prepared = append(h.prepared, cfg)
	if h.fail != nil {
		return nil, h.fail
	}
	return func() { *h.commits = append(*h.commits, h.name) }, nil
}

// reloadFixture is a running pipeline built from the config file it
// returns, which a test rewrites before reloading.
type reloadFixture struct {
	path    string
	dir     string
	commits []string
}

func newReloadFixture(t *testing.T, body string, handlers ...*reloadable) *reloadFixture {
	t.Helper()
	root := t.TempDir()
	f := &reloadFixture{path: filepath.Join(root, "sdns.conf"), dir: filepath.Join(root, "db")}
	f.write(t, body)
	cfg, err := config.Load(f.path, "test")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	Reset()
	t.Cleanup(Reset)
	for _, h := range handlers {
		h.commits = &f.commits
		DefaultRegistry.Register(h.name, func(*config.Config) Handler { return h })
	}
	Setup(cfg)
	return f
}

func (f *reloadFixture) write(t *testing.T, body string) {
	t.Helper()
	content := "directory = '" + f.dir + "'\nipv6access = true\ndnssec = \"off\"\nrootservers = [\"192.0.2.1:53\"]\n" + body
	if err := os.WriteFile(f.path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReloadRejectsAFileTheGateRefuses(t *testing.T) {
	owner := &reloadable{name: "acl", keys: []string{"accesslist"}}
	f := newReloadFixture(t, "", owner)

	for _, body := range []string{"accesslist = [\"not a cidr\"]\n", "nosuchkey = 1\n"} {
		f.write(t, body)
		if r := Reload(f.path); r.Outcome != ReloadRejected || r.Err == nil {
			t.Fatalf("%q: outcome %q err %v, want rejected", body, r.Outcome, r.Err)
		}
	}
	if err := os.Remove(f.path); err != nil {
		t.Fatal(err)
	}
	if r := Reload(f.path); r.Outcome != ReloadRejected {
		t.Fatalf("missing file: outcome %q, want rejected", r.Outcome)
	}
	if _, err := os.Stat(f.path); !os.IsNotExist(err) {
		t.Fatal("a reload generated the missing file")
	}
	if len(owner.prepared) != 0 {
		t.Fatal("an owner was asked to prepare a refused file")
	}
}

func TestReloadOfTheSameFileChangesNothing(t *testing.T) {
	owner := &reloadable{name: "acl", keys: []string{"accesslist"}}
	f := newReloadFixture(t, "accesslist = [\"192.0.2.0/24\"]\n", owner)

	if r := Reload(f.path); r.Outcome != ReloadUnchanged {
		t.Fatalf("outcome %q (%v, restart %v), want unchanged", r.Outcome, r.Applied, r.Restart)
	}
	if len(owner.prepared) != 0 {
		t.Fatal("an owner prepared for a file that changed nothing")
	}
}

func TestReloadAppliesWhatAnOwnerDeclares(t *testing.T) {
	owner := &reloadable{name: "acl", keys: []string{"accesslist"}}
	other := &reloadable{name: "views", keys: []string{"views"}}
	f := newReloadFixture(t, "", owner, other)

	f.write(t, "accesslist = [\"192.0.2.0/24\"]\n")
	r := Reload(f.path)
	if r.Outcome != ReloadApplied || !slices.Equal(r.Applied, []string{"accesslist"}) {
		t.Fatalf("outcome %q applied %v, want applied [accesslist]", r.Outcome, r.Applied)
	}
	if len(owner.prepared) != 1 || !slices.Equal(owner.prepared[0].AccessList, []string{"192.0.2.0/24"}) {
		t.Fatalf("owner prepared %d times with %v", len(owner.prepared), owner.prepared)
	}
	if len(other.prepared) != 0 {
		t.Fatal("a handler whose keys did not change was asked to prepare")
	}
	if !slices.Equal(f.commits, []string{"acl"}) {
		t.Fatalf("commits %v, want [acl]", f.commits)
	}

	// The next reload compares against what was applied.
	if r := Reload(f.path); r.Outcome != ReloadUnchanged {
		t.Fatalf("second reload of the same file: outcome %q, want unchanged", r.Outcome)
	}
}

// One owner refusing leaves every owner as it was: none commits.
func TestReloadCommitsNothingWhenAnOwnerRefuses(t *testing.T) {
	first := &reloadable{name: "acl", keys: []string{"accesslist"}}
	second := &reloadable{name: "views", keys: []string{"views"}, fail: errors.New("bad view")}
	f := newReloadFixture(t, "", first, second)

	f.write(t, "accesslist = [\"192.0.2.0/24\"]\n[[views]]\nzone = \"office\"\nnetworks = [\"192.0.2.0/24\"]\nanswers = [\"printer.local. 60 IN A 192.0.2.10\"]\n")
	r := Reload(f.path)
	if r.Outcome != ReloadRejected || r.Err == nil {
		t.Fatalf("outcome %q err %v, want rejected", r.Outcome, r.Err)
	}
	if len(f.commits) != 0 {
		t.Fatalf("commits %v after a refusal, want none", f.commits)
	}

	// Nothing was applied, so the same change is still pending.
	second.fail = nil
	if r := Reload(f.path); r.Outcome != ReloadApplied || len(f.commits) != 2 {
		t.Fatalf("retry: outcome %q commits %v, want both applied", r.Outcome, f.commits)
	}
}

// A changed key no running handler applies needs a restart. It is reported
// on every reload until the file goes back, while live keys still apply.
func TestReloadReportsKeysThatNeedARestart(t *testing.T) {
	owner := &reloadable{name: "acl", keys: []string{"accesslist"}}
	f := newReloadFixture(t, "", owner)

	f.write(t, "bind = \"127.0.0.1:5353\"\naccesslist = [\"192.0.2.0/24\"]\n")
	r := Reload(f.path)
	if r.Outcome != ReloadRestartNeeded || !slices.Equal(r.Restart, []string{"bind"}) ||
		!slices.Equal(r.Applied, []string{"accesslist"}) {
		t.Fatalf("outcome %q restart %v applied %v", r.Outcome, r.Restart, r.Applied)
	}
	if r := Reload(f.path); r.Outcome != ReloadRestartNeeded || !slices.Equal(r.Restart, []string{"bind"}) {
		t.Fatalf("second reload: outcome %q restart %v, want bind again", r.Outcome, r.Restart)
	}

	f.write(t, "accesslist = [\"192.0.2.0/24\"]\n")
	if r := Reload(f.path); r.Outcome != ReloadUnchanged {
		t.Fatalf("bind back as started: outcome %q restart %v, want unchanged", r.Outcome, r.Restart)
	}
}

// The cookie secret Load generated survives a file that names none; a file
// that names a different one needs a restart.
func TestReloadKeepsTheGeneratedCookieSecret(t *testing.T) {
	f := newReloadFixture(t, "")
	if r := Reload(f.path); r.Outcome != ReloadUnchanged {
		t.Fatalf("outcome %q restart %v, want unchanged", r.Outcome, r.Restart)
	}
	f.write(t, "cookiesecret = \"00112233445566778899aabbccddeeff\"\n")
	if r := Reload(f.path); !slices.Equal(r.Restart, []string{"cookiesecret"}) {
		t.Fatalf("restart %v, want [cookiesecret]", r.Restart)
	}
}

func TestReloadSetsTheLogLevel(t *testing.T) {
	old := zlog.Default()
	t.Cleanup(func() { zlog.SetDefault(old) })
	logger := zlog.NewStructured()
	logger.SetLevel(zlog.LevelInfo)
	zlog.SetDefault(logger)

	f := newReloadFixture(t, "")
	f.write(t, "loglevel = \"debug\"\n")
	if r := Reload(f.path); r.Outcome != ReloadApplied || !slices.Equal(r.Applied, []string{"loglevel"}) {
		t.Fatalf("outcome %q applied %v", r.Outcome, r.Applied)
	}
	if got := zlog.Default().GetLevel(); got != zlog.LevelDebug {
		t.Fatalf("level %v, want debug", got)
	}
}
