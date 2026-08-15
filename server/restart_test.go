package server

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/semihalev/sdns/config"
)

// TestStoppedMeansTheAddressIsFree pins what Stopped() is used for.
//
// sdns.go polls it to decide that a shutdown is complete. The only thing
// that decision is ever used for is doing something else with the
// resources the server held — above all, binding the same address again.
// If Stopped() can be true while a socket is still open, an in-process
// restart fails on "address already in use", and it fails intermittently,
// which is the worst way for it to fail.
func TestStoppedMeansTheAddressIsFree(t *testing.T) {
	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.LocalAddr().String()
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}

	cfg := new(config.Config)
	cfg.Bind = addr
	cfg.QueryTimeout.Duration = time.Second

	for i := range 25 {
		srv := New(cfg)
		ctx, cancel := context.WithCancel(context.Background())
		if err := srv.Run(ctx); err != nil {
			cancel()
			t.Fatalf("restart %d: %v", i, err)
		}

		deadline := time.Now().Add(2 * time.Second)
		for !srv.HasListener("udp") || !srv.HasListener("tcp") {
			if time.Now().After(deadline) {
				cancel()
				t.Fatalf("restart %d: listeners never came up", i)
			}
			time.Sleep(time.Millisecond)
		}

		cancel()
		deadline = time.Now().Add(5 * time.Second)
		for !srv.Stopped() {
			if time.Now().After(deadline) {
				t.Fatalf("restart %d: never reported stopped", i)
			}
			time.Sleep(time.Millisecond)
		}
		srv.Stop()
	}
}

// TestStoppedIsNotAheadOfTheSockets is the same property stated directly:
// the moment the server calls itself stopped, both of its addresses must
// be bindable by somebody else.
func TestStoppedIsNotAheadOfTheSockets(t *testing.T) {
	probe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.LocalAddr().String()
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}

	cfg := new(config.Config)
	cfg.Bind = addr
	cfg.QueryTimeout.Duration = time.Second

	for i := range 25 {
		srv := New(cfg)
		ctx, cancel := context.WithCancel(context.Background())
		if err := srv.Run(ctx); err != nil {
			cancel()
			t.Fatalf("round %d: %v", i, err)
		}
		deadline := time.Now().Add(2 * time.Second)
		for !srv.HasListener("udp") || !srv.HasListener("tcp") {
			if time.Now().After(deadline) {
				cancel()
				t.Fatalf("round %d: listeners never came up", i)
			}
			time.Sleep(time.Millisecond)
		}
		cancel()
		for !srv.Stopped() {
			time.Sleep(time.Millisecond)
		}
		srv.Stop()

		// Stopped() has just said the server is done with them.
		var held []string
		if pc, err := net.ListenPacket("udp", addr); err != nil {
			held = append(held, fmt.Sprintf("udp: %v", err))
		} else {
			_ = pc.Close()
		}
		if ln, err := net.Listen("tcp", addr); err != nil {
			held = append(held, fmt.Sprintf("tcp: %v", err))
		} else {
			_ = ln.Close()
		}
		if len(held) > 0 {
			t.Fatalf("round %d: the server reported stopped while it still held "+
				"%s — an in-process restart binds these next", i, strings.Join(held, ", "))
		}
	}
}

// TestQUICListenersReleasePortsBeforeStopped is the same property with
// QUIC in the picture, which is where it was actually broken.
//
// http3 and DoQ are handed a PacketConn they do not own: their accept
// loop returns the moment the server stops accepting, and the socket
// stays open until the supervisor closes it a few statements later. A
// Stopped() built on the Serve goroutine count alone therefore answered
// "done" with the UDP port still bound, and the next bind failed with
// "address already in use" — rarely, which is the worst frequency for
// this kind of thing.
//
// The poll below is tight on purpose. Production polls every 100ms and
// so almost always steps over the window; a regression here would be
// invisible at that cadence and visible in the field.
func TestQUICListenersReleasePortsBeforeStopped(t *testing.T) {
	tmpDir := t.TempDir()
	cert, key := generateTestCert(t, "restart.example.com")
	certPath := tmpDir + "/cert.pem"
	keyPath := tmpDir + "/key.pem"
	writeCertAndKey(t, certPath, keyPath, cert, key)

	// One at a time: DoH's listener pair already claims its UDP port for
	// HTTP/3, so pointing DoQ at the same address would only prove that
	// two listeners cannot share it.
	for _, tc := range []struct {
		name  string
		proto string
		bind  func(cfg *config.Config, addr string)
	}{
		{
			name:  "doq",
			proto: "doq",
			bind:  func(cfg *config.Config, addr string) { cfg.BindDOQ = addr },
		},
		{
			name:  "doh3",
			proto: "doh3",
			bind:  func(cfg *config.Config, addr string) { cfg.BindDOH = addr },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probe, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			quicAddr := probe.LocalAddr().String()
			if err := probe.Close(); err != nil {
				t.Fatal(err)
			}

			for i := range 25 {
				cfg := &config.Config{
					Bind:           "127.0.0.1:0",
					TLSCertificate: certPath,
					TLSPrivateKey:  keyPath,
					QueryTimeout:   config.Duration{Duration: time.Second},
				}
				tc.bind(cfg, quicAddr)

				srv := New(cfg)
				ctx, cancel := context.WithCancel(context.Background())
				if err := srv.Run(ctx); err != nil {
					cancel()
					t.Fatalf("round %d: %v", i, err)
				}
				deadline := time.Now().Add(3 * time.Second)
				for !srv.HasListener(tc.proto) {
					if time.Now().After(deadline) {
						cancel()
						t.Skipf("%s did not come up on this host", tc.proto)
					}
					time.Sleep(time.Millisecond)
				}

				cancel()
				for !srv.Stopped() {
					runtime.Gosched()
				}
				srv.Stop()

				// Stopped() has just said so; the QUIC port must be free.
				pc, err := net.ListenPacket("udp", quicAddr)
				if err != nil {
					t.Fatalf("round %d: the server reported stopped while the %s "+
						"listener still held %s: %v", i, tc.proto, quicAddr, err)
				}
				if err := pc.Close(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
