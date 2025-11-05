package dnstap

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/mock"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.Config
		want *Dnstap
	}{
		{
			name: "with custom identity and version",
			cfg: &config.Config{
				DnstapSocket:        "/tmp/test.sock",
				DnstapIdentity:      "test-server",
				DnstapVersion:       "1.0.0",
				DnstapLogQueries:    true,
				DnstapLogResponses:  true,
				DnstapFlushInterval: 5,
			},
			want: &Dnstap{
				identity:      []byte("test-server"),
				version:       []byte("1.0.0"),
				socketPath:    "/tmp/test.sock",
				logQueries:    true,
				logResponses:  true,
				flushInterval: 5 * time.Second,
			},
		},
		{
			name: "with default identity and version",
			cfg: &config.Config{
				DnstapSocket:       "/tmp/test.sock",
				DnstapLogQueries:   true,
				DnstapLogResponses: false,
			},
			want: &Dnstap{
				version:      []byte("sdns"),
				socketPath:   "/tmp/test.sock",
				logQueries:   true,
				logResponses: false,
			},
		},
		{
			name: "disabled",
			cfg:  &config.Config{},
			want: &Dnstap{
				version: []byte("sdns"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := New(tt.cfg).(*Dnstap)

			if tt.cfg.DnstapSocket != "" && (tt.cfg.DnstapLogQueries || tt.cfg.DnstapLogResponses) {
				// Close the goroutine
				close(d.done)
				time.Sleep(100 * time.Millisecond)
			}

			if string(d.version) != string(tt.want.version) {
				t.Errorf("version = %s, want %s", d.version, tt.want.version)
			}
			if tt.want.identity != nil && string(d.identity) != string(tt.want.identity) {
				t.Errorf("identity = %s, want %s", d.identity, tt.want.identity)
			}
			if d.socketPath != tt.want.socketPath {
				t.Errorf("socketPath = %s, want %s", d.socketPath, tt.want.socketPath)
			}
			if d.logQueries != tt.want.logQueries {
				t.Errorf("logQueries = %v, want %v", d.logQueries, tt.want.logQueries)
			}
			if d.logResponses != tt.want.logResponses {
				t.Errorf("logResponses = %v, want %v", d.logResponses, tt.want.logResponses)
			}
		})
	}
}

func TestName(t *testing.T) {
	d := &Dnstap{}
	if name := d.Name(); name != "dnstap" {
		t.Errorf("Name() = %s, want dnstap", name)
	}
}

func TestServeDNS(t *testing.T) {
	// Create a temporary socket for testing
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	// Start a mock dnstap server
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverDone := make(chan struct{})
	messages := make(chan *DnstapMessage, 10)

	go func() {
		defer close(serverDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		for {
			// Read frame length
			var length uint32
			if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
				if err != io.EOF {
					t.Logf("Error reading frame length: %v", err)
				}
				return
			}

			// Read frame data
			data := make([]byte, length)
			if _, err := io.ReadFull(conn, data); err != nil {
				t.Logf("Error reading frame data: %v", err)
				return
			}

			// Decode message
			msg := decodeMessage(data)
			if msg != nil {
				messages <- msg
			}
		}
	}()

	// Create dnstap middleware
	cfg := &config.Config{
		DnstapSocket:        socketPath,
		DnstapIdentity:      "test",
		DnstapVersion:       "1.0",
		DnstapLogQueries:    true,
		DnstapLogResponses:  true,
		DnstapFlushInterval: 1,
	}
	d := New(cfg).(*Dnstap)
	defer d.Close()

	// Wait for connection
	time.Sleep(200 * time.Millisecond)

	// Create test request
	req := &dns.Msg{
		MsgHdr: dns.MsgHdr{Id: 1234},
		Question: []dns.Question{
			{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		},
	}

	// Create test response
	res := &dns.Msg{
		MsgHdr: dns.MsgHdr{Id: 1234, Response: true},
		Question: []dns.Question{
			{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		},
		Answer: []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.IPv4(93, 184, 216, 34),
			},
		},
	}

	// Test with queries and responses enabled
	w := mock.NewWriter("udp", "127.0.0.1:53")

	ctx := context.Background()
	ch := middleware.NewChain([]middleware.Handler{
		middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
			rw := ch.Writer.(*responseWriter)
			rw.WriteMsg(res) //nolint:gosec // G104 - test mock
		}),
	})
	ch.Reset(w, req)

	d.ServeDNS(ctx, ch)

	// Wait for messages
	time.Sleep(100 * time.Millisecond)

	// Verify we received messages
	msgCount := 0
	timeout := time.After(2 * time.Second)
loop:
	for {
		select {
		case msg := <-messages:
			if msg != nil {
				msgCount++
				if msgCount >= 2 {
					break loop
				}
			}
		case <-timeout:
			break loop
		}
	}

	if msgCount < 2 {
		t.Errorf("Expected at least 2 messages (query and response), got %d", msgCount)
	}
}

func TestServeDNS_Disabled(t *testing.T) {
	d := &Dnstap{
		logQueries:   true,
		logResponses: true,
	}

	req := &dns.Msg{
		Question: []dns.Question{
			{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		},
	}

	w := mock.NewWriter("udp", "127.0.0.1:53")
	called := false

	ctx := context.Background()
	ch := middleware.NewChain([]middleware.Handler{
		middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
			called = true
		}),
	})
	ch.Reset(w, req)

	d.ServeDNS(ctx, ch)

	if !called {
		t.Error("Next handler was not called when dnstap is disabled")
	}
}

func TestLogMessage(t *testing.T) {
	d := &Dnstap{
		identity:     []byte("test-server"),
		version:      []byte("1.0.0"),
		messageQueue: make(chan *DnstapMessage, 10),
	}

	req := &dns.Msg{
		MsgHdr: dns.MsgHdr{Id: 1234},
		Question: []dns.Question{
			{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		},
	}

	res := &dns.Msg{
		MsgHdr: dns.MsgHdr{Id: 1234, Response: true},
		Answer: []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET},
				A:   net.IPv4(1, 2, 3, 4),
			},
		},
	}

	tests := []struct {
		name     string
		proto    string
		addr     string
		query    *dns.Msg
		response *dns.Msg
		isQuery  bool
		wantType MessageType
	}{
		{
			name:     "UDP query",
			proto:    "udp",
			addr:     "127.0.0.1:12345",
			query:    req,
			response: nil,
			isQuery:  true,
			wantType: MessageTypeQuery,
		},
		{
			name:     "TCP response",
			proto:    "tcp",
			addr:     "127.0.0.1:12345",
			query:    req,
			response: res,
			isQuery:  false,
			wantType: MessageTypeResponse,
		},
		{
			name:     "IPv6 query",
			proto:    "udp",
			addr:     "[::1]:12345",
			query:    req,
			response: nil,
			isQuery:  true,
			wantType: MessageTypeQuery,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := mock.NewWriter(tt.proto, tt.addr)

			d.logMessage(w, tt.query, tt.response, time.Now(), tt.isQuery)

			select {
			case msg := <-d.messageQueue:
				if msg.Type != tt.wantType {
					t.Errorf("Message type = %v, want %v", msg.Type, tt.wantType)
				}
				if !bytes.Equal(msg.Identity, d.identity) {
					t.Errorf("Identity = %s, want %s", msg.Identity, d.identity)
				}
				if !bytes.Equal(msg.Version, d.version) {
					t.Errorf("Version = %s, want %s", msg.Version, d.version)
				}
			case <-time.After(100 * time.Millisecond):
				t.Fatal("No message received")
			}
		})
	}
}

func TestLogMessage_QueueFull(t *testing.T) {
	d := &Dnstap{
		messageQueue: make(chan *DnstapMessage, 1),
	}

	// Fill the queue
	d.messageQueue <- &DnstapMessage{}

	req := &dns.Msg{
		Question: []dns.Question{
			{Name: "example.com.", Qtype: dns.TypeA},
		},
	}

	w := mock.NewWriter("udp", "127.0.0.1:53")

	// This should not block
	d.logMessage(w, req, nil, time.Now(), true)

	// Verify queue still has only 1 message
	if len(d.messageQueue) != 1 {
		t.Errorf("Queue length = %d, want 1", len(d.messageQueue))
	}
}

func TestReconnect(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	d := &Dnstap{
		socketPath:     socketPath,
		reconnectDelay: 100 * time.Millisecond,
		done:           make(chan struct{}),
	}

	// Test reconnect when no server is available
	d.reconnect()
	time.Sleep(50 * time.Millisecond)

	// Verify disconnected state
	d.mu.RLock()
	if d.conn != nil {
		t.Error("Expected conn to be nil after failed reconnect")
	}
	d.mu.RUnlock()
}

func TestClose(t *testing.T) {
	d := &Dnstap{
		done:         make(chan struct{}),
		messageQueue: make(chan *DnstapMessage, 10),
	}

	err := d.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// Verify channels are closed
	select {
	case <-d.done:
		// Expected
	default:
		t.Error("done channel was not closed")
	}
}

func TestResponseWriter(t *testing.T) {
	d := &Dnstap{
		messageQueue: make(chan *DnstapMessage, 10),
		identity:     []byte("test"),
		version:      []byte("1.0"),
	}

	req := &dns.Msg{
		Question: []dns.Question{
			{Name: "example.com.", Qtype: dns.TypeA},
		},
	}

	res := &dns.Msg{
		MsgHdr: dns.MsgHdr{Response: true},
		Answer: []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET},
				A:   net.IPv4(1, 2, 3, 4),
			},
		},
	}

	w := mock.NewWriter("udp", "127.0.0.1:53")
	rw := &responseWriter{
		ResponseWriter: w,
		query:          req,
		queryTime:      time.Now(),
		dnstap:         d,
	}

	err := rw.WriteMsg(res)
	if err != nil {
		t.Errorf("WriteMsg() error = %v", err)
	}

	// Verify message was logged
	select {
	case msg := <-d.messageQueue:
		if msg.Type != MessageTypeResponse {
			t.Errorf("Expected MessageTypeResponse, got %v", msg.Type)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("No message received")
	}
}

func TestIsEnabled(t *testing.T) {
	d := &Dnstap{}

	// Test when conn is nil
	if d.isEnabled() {
		t.Error("Expected isEnabled() to return false when conn is nil")
	}

	// Create a mock connection
	// Use pipe to create a real connection
	r, w := net.Pipe()
	defer r.Close()
	defer w.Close()

	d.mu.Lock()
	d.conn = w
	d.mu.Unlock()

	// Test when conn is set
	if !d.isEnabled() {
		t.Error("Expected isEnabled() to return true when conn is set")
	}
}

func TestEncodeMessage(t *testing.T) {
	d := &Dnstap{}

	msg := &DnstapMessage{
		Type:         MessageTypeQuery,
		Identity:     []byte("test"),
		Version:      []byte("1.0"),
		QueryAddress: net.IPv4(127, 0, 0, 1),
		QueryPort:    53,
		Protocol:     "UDP",
		QueryTime:    time.Unix(1234567890, 0),
		QueryMessage: []byte("test query"),
		ResponseTime: time.Unix(1234567891, 0),
		ResponseMsg:  []byte("test response"),
	}

	encoded := d.encodeMessage(msg)

	// Verify encoding
	if encoded[0] != byte(MessageTypeQuery) {
		t.Errorf("Expected first byte to be %d, got %d", MessageTypeQuery, encoded[0])
	}

	// Decode and verify identity
	identityLen := int(encoded[1])<<8 | int(encoded[2])
	if identityLen != len(msg.Identity) {
		t.Errorf("Identity length = %d, want %d", identityLen, len(msg.Identity))
	}

	identity := encoded[3 : 3+identityLen]
	if !bytes.Equal(identity, msg.Identity) {
		t.Errorf("Identity = %s, want %s", identity, msg.Identity)
	}
}

func TestWriteFrame(t *testing.T) {
	// Create a pipe for testing
	r, w := net.Pipe()
	defer r.Close()
	defer w.Close()

	d := &Dnstap{}
	testData := []byte("test frame data")

	// Write in a goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- d.writeFrame(w, testData)
	}()

	// Read and verify
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		t.Fatalf("Failed to read length: %v", err)
	}

	if length != uint32(len(testData)) { //nolint:gosec // G115 - test data length is small
		t.Errorf("Frame length = %d, want %d", length, len(testData))
	}

	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		t.Fatalf("Failed to read data: %v", err)
	}

	if !bytes.Equal(data, testData) {
		t.Errorf("Frame data = %s, want %s", data, testData)
	}

	// Check write error
	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("writeFrame() error = %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("writeFrame() did not complete")
	}
}

func TestWriteFrame_Error(t *testing.T) {
	// Create a pipe and close the write end immediately
	r, w := net.Pipe()
	r.Close() //nolint:gosec // G104 - test cleanup
	w.Close() //nolint:gosec // G104 - test cleanup

	d := &Dnstap{}
	testData := []byte("test frame data")

	// This should fail
	err := d.writeFrame(w, testData)
	if err == nil {
		t.Error("Expected error when writing to closed connection")
	}
}

func TestWriteMessage_NoConnection(t *testing.T) {
	d := &Dnstap{
		messageQueue: make(chan *DnstapMessage, 10),
	}

	msg := &DnstapMessage{
		Type:     MessageTypeQuery,
		Identity: []byte("test"),
		Version:  []byte("1.0"),
	}

	// Should not panic when conn is nil
	d.writeMessage(msg)
}

func TestWriteMessage_Error(t *testing.T) {
	// Create a temporary socket path
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	// Create a pipe and close it to simulate write error
	r, w := net.Pipe()
	r.Close() //nolint:gosec // G104 - test cleanup

	d := &Dnstap{
		socketPath:     socketPath,
		messageQueue:   make(chan *DnstapMessage, 10),
		done:           make(chan struct{}),
		reconnectDelay: 10 * time.Millisecond,
	}

	d.mu.Lock()
	d.conn = w
	d.mu.Unlock()

	msg := &DnstapMessage{
		Type:     MessageTypeQuery,
		Identity: []byte("test"),
		Version:  []byte("1.0"),
	}

	// This should trigger reconnect
	d.writeMessage(msg)

	// Give reconnect time to start
	time.Sleep(20 * time.Millisecond)

	// Stop the reconnect goroutine
	close(d.done)

	// Clean up
	w.Close() //nolint:gosec // G104 - test cleanup

	// Give time for goroutine to stop
	time.Sleep(20 * time.Millisecond)
}

func TestConnect(t *testing.T) {
	// Test connect with valid socket
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	// Start a listener
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	// Accept connections in goroutine
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close() //nolint:gosec // G104 - test mock
		}
	}()

	d := &Dnstap{
		socketPath:     socketPath,
		reconnectDelay: 100 * time.Millisecond,
		done:           make(chan struct{}),
	}

	// This should succeed
	d.connect()

	// Verify connected
	d.mu.RLock()
	connected := d.conn != nil
	d.mu.RUnlock()

	if !connected {
		t.Error("Expected to be connected")
	}

	// Clean up
	d.disconnect()
}

func TestRun(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	// Start a listener
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	// Accept connections
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			// Keep connection open
			go func(c net.Conn) {
				buf := make([]byte, 1024)
				for {
					_, err := c.Read(buf)
					if err != nil {
						c.Close() //nolint:gosec // G104 - test cleanup
						return
					}
				}
			}(conn)
		}
	}()

	d := &Dnstap{
		socketPath:     socketPath,
		reconnectDelay: 100 * time.Millisecond,
		done:           make(chan struct{}),
		messageQueue:   make(chan *DnstapMessage, 10),
		flushInterval:  100 * time.Millisecond,
	}

	// Start run in goroutine
	go d.run()

	// Wait for connection
	time.Sleep(200 * time.Millisecond)

	// Send a test message
	testMsg := &DnstapMessage{
		Type:     MessageTypeQuery,
		Identity: []byte("test"),
		Version:  []byte("1.0"),
		Protocol: "UDP",
	}

	d.messageQueue <- testMsg

	// Give it time to process
	time.Sleep(100 * time.Millisecond)

	// Stop
	close(d.done)

	// Give it time to shutdown
	time.Sleep(100 * time.Millisecond)
}

// Helper function to decode messages for testing.
func decodeMessage(data []byte) *DnstapMessage {
	if len(data) < 1 {
		return nil
	}

	msg := &DnstapMessage{
		Type: MessageType(data[0]),
	}

	pos := 1

	// Identity
	if pos+2 > len(data) {
		return nil
	}
	identityLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2
	if pos+identityLen > len(data) {
		return nil
	}
	msg.Identity = data[pos : pos+identityLen]
	pos += identityLen

	// Version
	if pos+2 > len(data) {
		return nil
	}
	versionLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2
	if pos+versionLen > len(data) {
		return nil
	}
	msg.Version = data[pos : pos+versionLen]
	// pos += versionLen // Position would be updated if we were reading more data

	// Continue decoding other fields as needed...

	return msg
}
