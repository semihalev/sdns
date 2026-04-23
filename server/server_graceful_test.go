package server

import (
	"context"
	"testing"
	"time"

	"github.com/semihalev/sdns/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	require.NotNil(t, s)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, s.Run(ctx))
	time.Sleep(100 * time.Millisecond)

	assert.True(t, s.HasListener("udp"), "UDP should be active")
	assert.True(t, s.HasListener("tcp"), "TCP should be active")

	assert.False(t, s.HasListener("tls"), "TLS should be disabled")
	assert.False(t, s.HasListener("doh"), "DoH should be disabled")
	assert.False(t, s.HasListener("doh3"), "DoH3 should be disabled")
	assert.False(t, s.HasListener("doq"), "DoQ should be disabled")

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
	require.NotNil(t, s)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, s.Run(ctx))
	time.Sleep(200 * time.Millisecond)

	assert.True(t, s.HasListener("udp"), "UDP should be active")
	assert.True(t, s.HasListener("tcp"), "TCP should be active")
	assert.True(t, s.HasListener("tls"), "TLS should be active")
	assert.True(t, s.HasListener("doh"), "DoH should be active")
	// DoH3 can fail on constrained CI runners (UDP buffer size, QUIC
	// features); leave it unchecked. DoQ reuses the same certificate.
	assert.True(t, s.HasListener("doq"), "DoQ should be active")

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
	require.NotNil(t, s)

	ctx, cancel := context.WithCancel(context.Background())
	require.NoError(t, s.Run(ctx))

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
	assert.True(t, s.HasListener("udp"))
	assert.True(t, s.HasListener("tcp"))
	assert.True(t, s.HasListener("doh"))
	assert.True(t, s.HasListener("doh3"))
	assert.True(t, s.HasListener("doq"))

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
	assert.False(t, s.HasListener("udp"), "UDP should no longer be serving")
	assert.False(t, s.HasListener("tcp"))
	assert.False(t, s.HasListener("doh"))
	assert.False(t, s.HasListener("doh3"))
	assert.False(t, s.HasListener("doq"))
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
		require.NotNil(t, s, "cycle %d: New", i)

		ctx, cancel := context.WithCancel(context.Background())
		require.NoError(t, s.Run(ctx), "cycle %d: Run", i)

		time.Sleep(100 * time.Millisecond)
		require.True(t, s.HasListener("doh3"), "cycle %d: DoH3 should bind on a fresh socket", i)
		require.True(t, s.HasListener("doq"), "cycle %d: DoQ should bind on a fresh socket", i)

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
