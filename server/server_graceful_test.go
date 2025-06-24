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
	// Test that server continues running even if TLS certificate fails
	cfg := &config.Config{
		Bind:           ":0", // Random port
		BindTLS:        ":0",
		BindDOH:        ":0",
		BindDOQ:        ":0",
		TLSCertificate: "/nonexistent/cert.pem",
		TLSPrivateKey:  "/nonexistent/key.pem",
		QueryTimeout:   config.Duration{Duration: 5 * time.Second},
	}

	s := New(cfg)
	require.NotNil(t, s)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start all services
	s.Run(ctx)

	// Give services time to start
	time.Sleep(100 * time.Millisecond)

	// Plain DNS services should still be running
	assert.True(t, s.udpStarted, "UDP service should be running")
	assert.True(t, s.tcpStarted, "TCP service should be running")

	// TLS services should not be running due to certificate error
	assert.False(t, s.tlsStarted, "TLS service should not be running")
	assert.False(t, s.dohStarted, "DoH service should not be running")
	assert.False(t, s.doh3Started, "DoH3 service should not be running")
	assert.False(t, s.doqStarted, "DoQ service should not be running")

	// Cancel context to stop services
	cancel()

	// Give services time to stop
	time.Sleep(100 * time.Millisecond)

	// All services should be stopped
	assert.True(t, s.Stopped(), "All services should be stopped")
}

func TestServerWithValidCertificate(t *testing.T) {
	// Create test certificate
	tmpDir := t.TempDir()
	cert, key := generateTestCert(t, "test.example.com")
	certPath := tmpDir + "/cert.pem"
	keyPath := tmpDir + "/key.pem"
	writeCertAndKey(t, certPath, keyPath, cert, key)

	cfg := &config.Config{
		Bind:           ":0", // Random port
		BindTLS:        ":0",
		BindDOH:        ":0",
		BindDOQ:        ":0",
		TLSCertificate: certPath,
		TLSPrivateKey:  keyPath,
		QueryTimeout:   config.Duration{Duration: 5 * time.Second},
	}

	s := New(cfg)
	require.NotNil(t, s)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start all services
	s.Run(ctx)

	// Give services more time to start
	time.Sleep(200 * time.Millisecond)

	// All services should be running (or attempted to start)
	assert.True(t, s.udpStarted, "UDP service should be running")
	assert.True(t, s.tcpStarted, "TCP service should be running")
	assert.True(t, s.tlsStarted, "TLS service should be running")
	assert.True(t, s.dohStarted, "DoH service should be running")
	// Note: DoH3 might fail on some systems due to QUIC requirements
	// Just check that DoQ is running as it uses the same certificate
	assert.True(t, s.doqStarted, "DoQ service should be running")

	// Stop the server
	cancel()
	time.Sleep(100 * time.Millisecond)

	// Clean up certificate manager
	s.Stop()
}
