// Command harness is the zerogate measurement subprocess: a real SDNS
// server with the default middleware chain, resolving against an in-process
// loopback authority, silent except for the mark protocol on stdin/stdout.
//
// Protocol (line-oriented):
//
//	child → parent:  READY <udp-bound-addr>
//	parent → child:  mark      → child runs two GCs, prints "MALLOCS <n>"
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
	"runtime"
	"strconv"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/zerogate"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/server"
	"github.com/semihalev/zlog/v2"

	"github.com/semihalev/sdns/middleware/accesslist"
	"github.com/semihalev/sdns/middleware/accesslog"
	"github.com/semihalev/sdns/middleware/as112"
	"github.com/semihalev/sdns/middleware/blocklist"
	"github.com/semihalev/sdns/middleware/cache"
	"github.com/semihalev/sdns/middleware/chaos"
	"github.com/semihalev/sdns/middleware/dns64"
	"github.com/semihalev/sdns/middleware/dnstap"
	"github.com/semihalev/sdns/middleware/edns"
	"github.com/semihalev/sdns/middleware/failover"
	"github.com/semihalev/sdns/middleware/forwarder"
	"github.com/semihalev/sdns/middleware/hostsfile"
	"github.com/semihalev/sdns/middleware/kubernetes"
	"github.com/semihalev/sdns/middleware/metrics"
	"github.com/semihalev/sdns/middleware/ratelimit"
	"github.com/semihalev/sdns/middleware/recovery"
	"github.com/semihalev/sdns/middleware/reflex"
	"github.com/semihalev/sdns/middleware/resolver"
	"github.com/semihalev/sdns/middleware/views"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "harness:", err)
		os.Exit(1)
	}
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
		ms    runtime.MemStats
		reply = make([]byte, 0, 32)
		mark  = []byte("mark")
		quit  = []byte("quit")
	)
	for scanner.Scan() {
		switch cmd := scanner.Bytes(); {
		case bytes.Equal(cmd, mark):
			// Two GCs: the first moves sync.Pool contents to the victim
			// cache, the second empties it — a mark must not credit pooled
			// storage that the collector could reclaim mid-window.
			runtime.GC()
			runtime.GC()
			runtime.ReadMemStats(&ms)
			reply = append(reply[:0], "MALLOCS "...)
			reply = strconv.AppendUint(reply, ms.Mallocs, 10)
			reply = append(reply, '\n')
			if _, err := os.Stdout.Write(reply); err != nil {
				return err
			}
		case bytes.Equal(cmd, quit):
			return nil
		}
	}
	return scanner.Err()
}

// registerDefaultChain mirrors the generated registry.go exactly: the named
// default configuration is the default chain, in the default order.
func registerDefaultChain() {
	middleware.Register("recovery", func(cfg *config.Config) middleware.Handler { return recovery.New(cfg) })
	middleware.Register("metrics", func(cfg *config.Config) middleware.Handler { return metrics.New(cfg) })
	middleware.Register("dnstap", dnstap.New)
	middleware.Register("accesslist", func(cfg *config.Config) middleware.Handler { return accesslist.New(cfg) })
	middleware.Register("ratelimit", func(cfg *config.Config) middleware.Handler { return ratelimit.New(cfg) })
	middleware.Register("reflex", func(cfg *config.Config) middleware.Handler { return reflex.New(cfg) })
	middleware.Register("edns", func(cfg *config.Config) middleware.Handler { return edns.New(cfg) })
	middleware.Register("accesslog", func(cfg *config.Config) middleware.Handler { return accesslog.New(cfg) })
	middleware.Register("chaos", func(cfg *config.Config) middleware.Handler { return chaos.New(cfg) })
	middleware.Register("hostsfile", func(cfg *config.Config) middleware.Handler { return hostsfile.New(cfg) })
	middleware.Register("views", func(cfg *config.Config) middleware.Handler { return views.New(cfg) })
	middleware.Register("blocklist", func(cfg *config.Config) middleware.Handler { return blocklist.New(cfg) })
	middleware.Register("as112", func(cfg *config.Config) middleware.Handler { return as112.New(cfg) })
	middleware.Register("kubernetes", func(cfg *config.Config) middleware.Handler { return kubernetes.New(cfg) })
	middleware.Register("dns64", func(cfg *config.Config) middleware.Handler { return dns64.New(cfg) })
	middleware.Register("cache", func(cfg *config.Config) middleware.Handler { return cache.New(cfg) })
	middleware.Register("failover", func(cfg *config.Config) middleware.Handler { return failover.New(cfg) })
	middleware.Register("resolver", func(cfg *config.Config) middleware.Handler { return resolver.New(cfg) })
	middleware.Register("forwarder", func(cfg *config.Config) middleware.Handler { return forwarder.New(cfg) })
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
