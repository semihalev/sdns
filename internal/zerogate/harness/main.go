// Command harness is the zerogate measurement subprocess: a real SDNS
// server with the default middleware chain, resolving against an in-process
// loopback authority, silent except for the mark protocol on stdin/stdout.
//
// Protocol (line-oriented):
//
//	child → parent:  READY <udp-bound-addr>
//	parent → child:  quiesce   → waits until no job slab is outstanding,
//	                             prints "QUIESCED ok" or "QUIESCED timeout"
//	parent → child:  mark      → two GCs, then
//	                             "MALLOCS <close> OPEN <open> SERVED <k>
//	                             OTHER <m> PARKED <p> UNKNOWN <u>":
//	                             close/open bracket the snapshot, so a
//	                             window's exact malloc delta (close minus
//	                             the previous open) excludes the
//	                             measurement's own cost;
//	                             k is the objects the server's own code
//	                             allocated on a serving goroutine (the
//	                             gate's exact verdict), m the objects
//	                             allocated anywhere else in the server —
//	                             p of them scheduler bookkeeping for a
//	                             parked serving goroutine — excluding the
//	                             harness's own machinery
//	parent → child:  offenders → "OFFENDER <objects> <func> <file:line>"
//	                             per allocating site since the previous
//	                             mark, terminated by "END"
//	parent → child:  quit      → child exits 0
//
// Environment: ZEROGATE_BIND is the listener bind address (parent-chosen
// free port). The authority port is self-chosen.
package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/zerogate"
	"github.com/semihalev/sdns/internal/zerogate/inject"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/defaults"
	"github.com/semihalev/sdns/server"
	"github.com/semihalev/zlog/v2"
)

// Every allocation is profiled, not one in every 512KB. The gate's
// question is not how much was allocated but whether the serving path
// allocated at all, and that question is only answerable if no
// allocation goes unrecorded. It has to be set before anything runs.
func init() { runtime.MemProfileRate = 1 }

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "harness:", err)
		os.Exit(1)
	}
}

// servingPrefix marks the goroutines that carry a query. An allocation
// with one of these frames on its stack was made while serving —
// whatever package it happens to live in, and however deep in the chain
// it is — which is exactly the thing the zero path claims not to do.
const servingPrefix = "github.com/semihalev/sdns/server."

// allocSite is one allocating stack, keyed by its program counters.
type allocSite struct {
	objects int64
	serving bool
	harness bool // the measurement's own machinery, not the server's
	// platform marks an allocation the runtime made on the server's
	// behalf rather than one the server's own code asked for: the
	// classic is a sudog, which the scheduler takes when a goroutine
	// parks — two workers meeting on one socket's write lock for an
	// instant. It is bookkeeping for blocking, bounded by the number of
	// Ps rather than by the number of queries, so it is held to not
	// scaling instead of to exactly zero. Nothing is hidden by that: a
	// buffer that really did escape into the socket write would grow
	// with the traffic, and the scaling verdict is where it would show.
	platform bool
	// truncated marks a stack that filled the profile record. A record
	// holds 32 program counters and keeps the innermost ones, so a deeper
	// stack loses its outer frames — including the goroutine's entry,
	// which is what says whether it was serving. Such a site cannot be
	// classified, and an unclassifiable allocation counts against the
	// exact verdict rather than falling into the residue: a gate that
	// answers "not proven" with "fine" is not a gate.
	truncated bool
	fn        string
	pos       string
	via       string // the first few non-runtime frames, innermost first
}

// profileStackDepth is the number of program counters runtime.MemProfile
// records per site (runtime.MemProfileRecord.Stack0).
const profileStackDepth = 32

// sudogAlloc is the runtime function that allocates a sudog: the record
// the scheduler keeps for a goroutine while it is parked on a channel, a
// select or a semaphore. Every park path in the runtime reaches it, and
// nothing else does.
const sudogAlloc = "runtime.acquireSudog"

// parkBookkeeping reports whether a stack is the scheduler recording a
// park rather than the server allocating. The frame itself is the test.
//
// Naming the allocating frame is what makes this narrow enough to be
// honest. Classifying by the caller instead does not work in either
// direction: a park on a channel shows the blocking function as its
// first non-runtime frame — server code, so a real park would be charged
// to the server — while exempting the packages parks tend to appear in,
// internal/poll and syscall, would take a buffer that genuinely escaped
// into a socket write out of the exact verdict along with them.
func parkBookkeeping(frames []string) bool {
	for _, fn := range frames {
		if fn == sudogAlloc {
			return true
		}
	}
	return false
}

// profile returns the live allocation profile keyed by stack. Records
// include fully freed objects: the claim is about allocating, not about
// retaining.
func profile() map[string]*allocSite {
	n, _ := runtime.MemProfile(nil, true)
	var records []runtime.MemProfileRecord
	for {
		records = make([]runtime.MemProfileRecord, n+64)
		var ok bool
		n, ok = runtime.MemProfile(records, true)
		if ok {
			records = records[:n]
			break
		}
	}

	sites := make(map[string]*allocSite, len(records))
	var key strings.Builder
	for i := range records {
		r := &records[i]
		stack := r.Stack()
		key.Reset()
		for _, pc := range stack {
			fmt.Fprintf(&key, "%x,", pc)
		}
		site := &allocSite{
			objects:   r.AllocObjects,
			truncated: len(stack) >= profileStackDepth,
		}
		frames := runtime.CallersFrames(stack)
		var trail, all []string
		for {
			f, more := frames.Next()
			all = append(all, f.Function)
			// The allocating frame is always runtime.mallocgc and its
			// helpers; what identifies a site is the first frame that is
			// ours, with a little of its caller for context.
			if !strings.HasPrefix(f.Function, "runtime.") && len(trail) < 3 {
				trail = append(trail, f.Function)
				if site.fn == "" {
					site.fn = f.Function
					site.pos = fmt.Sprintf("%s:%d", filepath.Base(f.File), f.Line)
				}
			}
			if strings.HasPrefix(f.Function, servingPrefix) {
				site.serving = true
			}
			if strings.HasPrefix(f.Function, "main.") {
				site.harness = true
			}
			if !more {
				break
			}
		}
		if site.fn == "" {
			site.fn, site.pos = "runtime", "?"
		}
		site.platform = parkBookkeeping(all)
		site.via = strings.Join(trail, " ← ")
		sites[key.String()] = site
	}
	return sites
}

// since totals what was allocated between two profiles, split three ways:
// served (on a serving goroutine), other (anywhere else in the server),
// and the harness's own measurement machinery, which is dropped.
//
// The measurement has to be excluded by name because it is not free:
// profiling every allocation means each snapshot walks thousands of
// records, and those allocations land in the window the snapshot opens.
// Charging them to the server would drown the very thing being measured
// — and a process-wide counter has no way to tell them apart, which is
// the second reason attribution is doing the work here.
func since(before, after map[string]*allocSite) (served, other, parked, unknown int64, offenders []*allocSite) {
	// ZEROGATE_ALL_SITES widens the report to every growing site, not
	// just the ones on a serving stack. The verdict never changes; it is
	// how the second, ops-relative verdict gets a name when it fires,
	// since what it catches is by definition off the serving stacks.
	all := os.Getenv("ZEROGATE_ALL_SITES") != ""
	for key, now := range after {
		grew := now.objects
		if was, ok := before[key]; ok {
			grew -= was.objects
		}
		if grew <= 0 {
			continue
		}
		switch {
		case now.harness:
			continue
		case now.serving && now.platform:
			// Scheduler bookkeeping on a serving stack: counted with the
			// rest, so the scaling verdict still covers it.
			parked += grew
			other += grew
		case now.serving:
			served += grew
		case now.truncated:
			// Too deep to classify: the frames that would say whether
			// this was serving fell off the end of the record. Counted
			// against the exact verdict, because the alternative is to
			// let anything deep enough walk past it.
			unknown += grew
		default:
			other += grew
		}
		if (now.serving && !now.platform) || now.truncated && !now.serving || all {
			offenders = append(offenders, &allocSite{
				objects: grew, serving: now.serving, fn: now.fn, pos: now.pos, via: now.via,
			})
		}
	}
	sort.Slice(offenders, func(i, j int) bool {
		return offenders[i].objects > offenders[j].objects
	})
	return served, other, parked, unknown, offenders
}

func run() error {
	// The control plane must be silent during measurement windows.
	logger := zlog.NewStructured()
	logger.SetWriter(io.Discard)
	logger.SetLevel(zlog.LevelFatal)
	zlog.SetDefault(logger)

	bind := os.Getenv("ZEROGATE_BIND")
	if bind == "" {
		return fmt.Errorf("ZEROGATE_BIND not set")
	}

	authorityAddr, err := startAuthority()
	if err != nil {
		return fmt.Errorf("authority: %w", err)
	}

	cfg, err := harnessConfig(bind, authorityAddr)
	if err != nil {
		return err
	}
	registerDefaultChain()
	middleware.Setup(cfg)

	srv := server.New(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Run(ctx); err != nil {
		return fmt.Errorf("server run: %w", err)
	}
	if err := awaitServing(srv); err != nil {
		return err
	}

	fmt.Printf("READY %s\n", bind)

	// The control protocol is on the measured side of the fence: a reply
	// formatted after the snapshot allocates inside the window that
	// snapshot opens, and those allocations are then charged to the
	// traffic. Reading and answering therefore borrow no allocator —
	// the command is compared as bytes, and the reply is appended into a
	// buffer that outlives every mark.
	scanner := bufio.NewScanner(os.Stdin)
	var (
		ms        runtime.MemStats
		reply     = make([]byte, 0, 64)
		mark      = []byte("mark")
		quiesce   = []byte("quiesce")
		offenders = []byte("offenders")
		quit      = []byte("quit")

		prev      map[string]*allocSite
		lastServe []*allocSite
	)
	for scanner.Scan() {
		switch cmd := scanner.Bytes(); {
		case bytes.Equal(cmd, quiesce):
			// The barrier the measurement is taken at: every job slab
			// back in its ring. A client's last reply says the bytes
			// left, not that the slab which carried them was released,
			// and the release is where the request's state is cleared.
			verdict := "timeout"
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				if srv.Quiesced() {
					verdict = "ok"
					break
				}
				time.Sleep(time.Millisecond)
			}
			// Slabs being home says the engines are done; it says nothing
			// about work they handed to someone else. Wait for the
			// process to stop allocating as well, so a refresh, a flush
			// or a log line that trails the traffic lands in the window
			// that caused it rather than in the next one. Best effort and
			// bounded: a process with a periodic background will never go
			// perfectly still, and the ops-relative verdicts are what
			// cover that.
			var prev, cur runtime.MemStats
			runtime.ReadMemStats(&prev)
			settled := false
			for still, tries := 0, 0; tries < 100; tries++ {
				time.Sleep(2 * time.Millisecond)
				runtime.ReadMemStats(&cur)
				if cur.Mallocs == prev.Mallocs {
					if still++; still == 3 {
						settled = true
						break
					}
					continue
				}
				still, prev = 0, cur
			}
			if verdict == "ok" && !settled {
				// Said plainly rather than swallowed. The window would
				// otherwise close over a process that is still allocating,
				// and whatever it is doing would be charged to the next
				// window instead of this one.
				verdict = "unsettled"
			}
			if _, err := fmt.Printf("QUIESCED %s\n", verdict); err != nil {
				return err
			}
		case bytes.Equal(cmd, mark):
			// Two GCs: the first moves sync.Pool contents to the victim
			// cache, the second empties it — a mark must not credit pooled
			// storage that the collector could reclaim mid-window. The
			// profile is only current as of the last collection, which is
			// the other reason they come first.
			runtime.GC()
			runtime.GC()
			runtime.ReadMemStats(&ms)
			// Read once to close the window and once to open the next,
			// with the snapshot between them. MemStats.Mallocs counts
			// every logical allocation — including the tiny ones the
			// profiler never sees, because an object that fits the
			// current 16-byte tiny block is returned before the sampling
			// code runs. It is the exact signal; it just cannot say who
			// allocated. Bracketing the snapshot keeps the measurement's
			// own cost out of both windows, which is what makes the
			// number usable at all.
			closeMallocs := ms.Mallocs
			now := profile()
			var served, other, parked, unknown int64
			if prev != nil {
				served, other, parked, unknown, lastServe = since(prev, now)
			}
			prev = now
			runtime.ReadMemStats(&ms)
			reply = append(reply[:0], "MALLOCS "...)
			reply = strconv.AppendUint(reply, closeMallocs, 10)
			reply = append(reply, " OPEN "...)
			reply = strconv.AppendUint(reply, ms.Mallocs, 10)
			reply = append(reply, " SERVED "...)
			reply = strconv.AppendInt(reply, served, 10)
			reply = append(reply, " OTHER "...)
			reply = strconv.AppendInt(reply, other, 10)
			reply = append(reply, " PARKED "...)
			reply = strconv.AppendInt(reply, parked, 10)
			reply = append(reply, " UNKNOWN "...)
			reply = strconv.AppendInt(reply, unknown, 10)
			reply = append(reply, '\n')
			if _, err := os.Stdout.Write(reply); err != nil {
				return err
			}
		case bytes.Equal(cmd, offenders):
			for _, o := range lastServe {
				if _, err := fmt.Printf("OFFENDER %d %s (%s)\n", o.objects, o.pos, o.via); err != nil {
					return err
				}
			}
			if _, err := fmt.Println("END"); err != nil {
				return err
			}
		case bytes.Equal(cmd, quit):
			return nil
		}
	}
	return scanner.Err()
}

// registerDefaultChain registers the named default configuration — the
// generated chain itself, so the gate cannot end up measuring a chain
// nobody runs.
func registerDefaultChain() {
	// The gate's negative controls, when asked for: middleware that
	// allocates on purpose, in the shapes attribution is weakest against.
	// It lives in its own package so the measurement's own exclusion does
	// not swallow it.
	if h := inject.New(os.Getenv("ZEROGATE_INJECT")); h != nil {
		middleware.Register("zerogateinject", func(*config.Config) middleware.Handler { return h })
	}
	defaults.Register()
}

func harnessConfig(bind, authorityAddr string) (*config.Config, error) {
	dir, err := os.MkdirTemp("", "zerogate")
	if err != nil {
		return nil, err
	}
	cfg := new(config.Config)
	cfg.Bind = bind
	cfg.RootServers = []string{authorityAddr}
	cfg.Root6Servers = nil
	// The shipped default. A prefetch-due hit deliberately leaves the byte
	// path (it needs a request copy for the refresh queue), so a gate that
	// disabled prefetching would be measuring a configuration nobody runs.
	// The corpus answers carry an hour's TTL, so a measurement window
	// never reaches the refresh threshold — what is measured is the hit,
	// with the feature that reshapes it enabled.
	cfg.Prefetch = 10
	// Validation stays off: the harness resolves against a loopback
	// authority that no real trust anchor covers, so "on" would fail every
	// warmup rather than exercise anything. What DNSSEC changes on the hit
	// path — the DO/no-DO body split — is measured directly by the cache's
	// own class tests instead.
	cfg.DNSSEC = "off"
	cfg.Maxdepth = 30
	cfg.Expire = 600
	cfg.CacheSize = 10240
	cfg.Timeout.Duration = 2 * time.Second
	cfg.QueryTimeout.Duration = 10 * time.Second
	cfg.Directory = dir
	cfg.IPv6Access = false
	cfg.CookieSecret = "6c6f6f6b61686172646c6f6f6b6168617264"
	return cfg, nil
}

func awaitServing(srv *server.Server) error {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if srv.HasListener("udp") && srv.HasListener("tcp") {
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("listeners did not start serving")
}

// startAuthority runs a loopback authority answering the corpus zone
// authoritatively — active only during warmup; measurement windows are
// hit-only and never reach it.
func startAuthority() (string, error) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(r)
		reply.Authoritative = true
		if len(r.Question) == 1 {
			q := r.Question[0]
			if q.Qtype == dns.TypeA && len(q.Name) > len(zerogate.Zone) &&
				dns.IsSubDomain(zerogate.Zone, q.Name) {
				reply.Answer = append(reply.Answer, &dns.A{
					Hdr: dns.RR_Header{
						Name: q.Name, Rrtype: dns.TypeA,
						Class: dns.ClassINET, Ttl: 3600,
					},
					A: net.IPv4(192, 0, 2, 10),
				})
			} else if q.Name != "." {
				reply.Rcode = dns.RcodeNameError
			}
		}
		_ = w.WriteMsg(reply)
	})
	srv := &dns.Server{Net: "udp", PacketConn: pc, Handler: mux}
	go func() { _ = srv.ActivateAndServe() }()
	return pc.LocalAddr().String(), nil
}
