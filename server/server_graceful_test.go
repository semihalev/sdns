package server

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/semihalev/sdns/config"
)

func TestServerGracefulDegradation(t *testing.T) {
	// Plain DNS still comes up when TLS material is missing — the TLS,
	// DoH, DoH3 and DoQ listeners mark themselves non-critical, log,
	// and let startup continue.
	cfg := &config.Config{
		Bind:           "127.0.0.1:0",
		BindTLS:        "127.0.0.1:0",
		BindDOH:        "127.0.0.1:0",
		BindDOQ:        "127.0.0.1:0",
		TLSCertificate: "/nonexistent/cert.pem",
		TLSPrivateKey:  "/nonexistent/key.pem",
		QueryTimeout:   config.Duration{Duration: 5 * time.Second},
	}

	s := New(cfg)
	if s == nil {
		t.Fatalf("s is nil")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := s.Run(ctx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	if !(s.HasListener("udp")) {
		t.Errorf("%s: s.HasListener('udp') is false", "UDP should be active")
	}
	if !(s.HasListener("tcp")) {
		t.Errorf("%s: s.HasListener('tcp') is false", "TCP should be active")
	}

	if s.HasListener("tls") {
		t.Errorf("%s: s.HasListener('tls') is true", "TLS should be disabled")
	}
	if s.HasListener("doh") {
		t.Errorf("%s: s.HasListener('doh') is true", "DoH should be disabled")
	}
	if s.HasListener("doh3") {
		t.Errorf("%s: s.HasListener('doh3') is true", "DoH3 should be disabled")
	}
	if s.HasListener("doq") {
		t.Errorf("%s: s.HasListener('doq') is true", "DoQ should be disabled")
	}

	cancel()

	deadline := time.Now().Add(5 * time.Second)
	for !s.Stopped() {
		if time.Now().After(deadline) {
			t.Fatal("server did not stop within deadline")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestServerWithValidCertificate(t *testing.T) {
	tmpDir := t.TempDir()
	cert, key := generateTestCert(t, "test.example.com")
	certPath := tmpDir + "/cert.pem"
	keyPath := tmpDir + "/key.pem"
	writeCertAndKey(t, certPath, keyPath, cert, key)

	cfg := &config.Config{
		Bind:           "127.0.0.1:0",
		BindTLS:        "127.0.0.1:0",
		BindDOH:        "127.0.0.1:0",
		BindDOQ:        "127.0.0.1:0",
		TLSCertificate: certPath,
		TLSPrivateKey:  keyPath,
		QueryTimeout:   config.Duration{Duration: 5 * time.Second},
	}

	s := New(cfg)
	if s == nil {
		t.Fatalf("s is nil")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := s.Run(ctx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	if !(s.HasListener("udp")) {
		t.Errorf("%s: s.HasListener('udp') is false", "UDP should be active")
	}
	if !(s.HasListener("tcp")) {
		t.Errorf("%s: s.HasListener('tcp') is false", "TCP should be active")
	}
	if !(s.HasListener("tls")) {
		t.Errorf("%s: s.HasListener('tls') is false", "TLS should be active")
	}
	if !(s.HasListener("doh")) {
		t.Errorf("%s: s.HasListener('doh') is false", "DoH should be active")
	}
	// DoH3 can fail on constrained CI runners (UDP buffer size, QUIC
	// features); leave it unchecked. DoQ reuses the same certificate.
	if !(s.HasListener("doq")) {
		t.Errorf("%s: s.HasListener('doq') is false", "DoQ should be active")
	}

	cancel()
	time.Sleep(100 * time.Millisecond)
	s.Stop()
}

// TestServerHasListenerReflectsServeState verifies that HasListener
// tracks "is actually serving right now", not merely "Bind succeeded".
// This is the behaviour the DoH3 / DoQ listeners need: QUIC bring-up
// happens inside Serve, so a listener can be bound but not serving
// if Serve's own setup fails.
func TestServerHasListenerReflectsServeState(t *testing.T) {
	tmpDir := t.TempDir()
	cert, key := generateTestCert(t, "test.example.com")
	certPath := tmpDir + "/cert.pem"
	keyPath := tmpDir + "/key.pem"
	writeCertAndKey(t, certPath, keyPath, cert, key)

	cfg := &config.Config{
		Bind:           "127.0.0.1:0",
		BindDOH:        "127.0.0.1:0",
		BindDOQ:        "127.0.0.1:0",
		TLSCertificate: certPath,
		TLSPrivateKey:  keyPath,
		QueryTimeout:   config.Duration{Duration: 5 * time.Second},
	}

	s := New(cfg)
	if s == nil {
		t.Fatalf("s is nil")
	}

	ctx, cancel := context.WithCancel(context.Background())
	if err := s.Run(ctx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Before Serve has had a chance to run, HasListener may be
	// false; give goroutines time to start.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.HasListener("udp") && s.HasListener("tcp") &&
			s.HasListener("doh") && s.HasListener("doh3") &&
			s.HasListener("doq") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !(s.HasListener("udp")) {
		t.Errorf("s.HasListener('udp') is false")
	}
	if !(s.HasListener("tcp")) {
		t.Errorf("s.HasListener('tcp') is false")
	}
	if !(s.HasListener("doh")) {
		t.Errorf("s.HasListener('doh') is false")
	}
	if !(s.HasListener("doh3")) {
		t.Errorf("s.HasListener('doh3') is false")
	}
	if !(s.HasListener("doq")) {
		t.Errorf("s.HasListener('doq') is false")
	}

	// Stop the server — every listener's Serve goroutine exits and
	// HasListener must flip back to false.
	cancel()
	stopDeadline := time.Now().Add(5 * time.Second)
	for !s.Stopped() {
		if time.Now().After(stopDeadline) {
			t.Fatal("server did not stop within deadline")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if s.HasListener("udp") {
		t.Errorf("%s: s.HasListener('udp') is true", "UDP should no longer be serving")
	}
	if s.HasListener("tcp") {
		t.Errorf("s.HasListener('tcp') is true")
	}
	if s.HasListener("doh") {
		t.Errorf("s.HasListener('doh') is true")
	}
	if s.HasListener("doh3") {
		t.Errorf("s.HasListener('doh3') is true")
	}
	if s.HasListener("doq") {
		t.Errorf("s.HasListener('doq') is true")
	}
}

// TestServerRestartReleasesSockets reproduces the graceful-restart case
// that the DoH3 / DoQ listeners used to break: the caller-owned UDP
// socket must be released when Shutdown runs, so a fresh server can
// bind the same addresses on the next pass.
func TestServerRestartReleasesSockets(t *testing.T) {
	tmpDir := t.TempDir()
	cert, key := generateTestCert(t, "test.example.com")
	certPath := tmpDir + "/cert.pem"
	keyPath := tmpDir + "/key.pem"
	writeCertAndKey(t, certPath, keyPath, cert, key)

	// Use fixed ports on loopback so the second Run must re-bind them.
	cfg := &config.Config{
		Bind:           "127.0.0.1:0",
		BindDOH:        "127.0.0.1:23234", // DoH3 also binds this UDP port
		BindDOQ:        "127.0.0.1:23235",
		TLSCertificate: certPath,
		TLSPrivateKey:  keyPath,
		QueryTimeout:   config.Duration{Duration: 5 * time.Second},
	}

	for i := 0; i < 2; i++ {
		s := New(cfg)
		if s == nil {
			t.Fatalf("%s: s is nil", fmt.Sprintf("cycle %d: New", i))
		}

		ctx, cancel := context.WithCancel(context.Background())
		if err := s.Run(ctx); err != nil {
			t.Fatalf("%s: unexpected error: %v", fmt.Sprintf("cycle %d: Run", i), err)
		}

		time.Sleep(100 * time.Millisecond)
		if !(s.HasListener("doh3")) {
			t.Fatalf("%s: s.HasListener('doh3') is false", fmt.Sprintf("cycle %d: DoH3 should bind on a fresh socket", i))
		}
		if !(s.HasListener("doq")) {
			t.Fatalf("%s: s.HasListener('doq') is false", fmt.Sprintf("cycle %d: DoQ should bind on a fresh socket", i))
		}

		cancel()

		deadline := time.Now().Add(5 * time.Second)
		for !s.Stopped() {
			if time.Now().After(deadline) {
				t.Fatalf("cycle %d: server did not stop within deadline", i)
			}
			time.Sleep(50 * time.Millisecond)
		}
		s.Stop()
	}
}
