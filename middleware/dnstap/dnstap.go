package dnstap

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/log"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
)

// MessageType represents dnstap message types
type MessageType uint32

const (
	MessageTypeQuery    MessageType = 1
	MessageTypeResponse MessageType = 2
)

// DnstapMessage represents a simplified dnstap message
type DnstapMessage struct {
	Type         MessageType
	Identity     []byte
	Version      []byte
	QueryAddress net.IP
	QueryPort    uint16
	Protocol     string
	QueryTime    time.Time
	QueryMessage []byte
	ResponseTime time.Time
	ResponseMsg  []byte
}

// Dnstap middleware for binary DNS logging
type Dnstap struct {
	identity      []byte
	version       []byte
	socketPath    string
	logQueries    bool
	logResponses  bool
	flushInterval time.Duration

	conn           net.Conn
	mu             sync.RWMutex
	done           chan struct{}
	reconnectDelay time.Duration
	messageQueue   chan *DnstapMessage
}

// New creates a new dnstap middleware
func New(cfg *config.Config) middleware.Handler {
	flushInterval := time.Duration(cfg.DnstapFlushInterval) * time.Second
	if flushInterval <= 0 {
		flushInterval = 5 * time.Second // Default flush interval
	}

	d := &Dnstap{
		socketPath:     cfg.DnstapSocket,
		logQueries:     cfg.DnstapLogQueries,
		logResponses:   cfg.DnstapLogResponses,
		flushInterval:  flushInterval,
		reconnectDelay: 5 * time.Second,
		done:           make(chan struct{}),
		messageQueue:   make(chan *DnstapMessage, 1000),
	}

	if cfg.DnstapIdentity != "" {
		d.identity = []byte(cfg.DnstapIdentity)
	} else {
		hostname, _ := os.Hostname()
		d.identity = []byte(hostname)
	}

	if cfg.DnstapVersion != "" {
		d.version = []byte(cfg.DnstapVersion)
	} else {
		d.version = []byte("sdns")
	}

	if d.socketPath != "" && (d.logQueries || d.logResponses) {
		go d.run()
	}

	return d
}

// Name returns the name of the middleware
func (d *Dnstap) Name() string {
	return "dnstap"
}

// ServeDNS logs DNS messages in dnstap format
func (d *Dnstap) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	w, req := ch.Writer, ch.Request

	if !d.isEnabled() {
		ch.Next(ctx)
		return
	}

	// Capture query time
	queryTime := time.Now()

	// Log query if enabled
	if d.logQueries {
		d.logMessage(w, req, nil, queryTime, true)
	}

	// Create response writer wrapper to capture response
	if d.logResponses {
		rw := &responseWriter{
			ResponseWriter: w,
			query:          req,
			queryTime:      queryTime,
			dnstap:         d,
		}
		ch.Writer = rw
	}

	ch.Next(ctx)
}

func (d *Dnstap) isEnabled() bool {
	d.mu.RLock()
	enabled := d.conn != nil
	d.mu.RUnlock()
	return enabled
}

func (d *Dnstap) run() {
	d.connect()

	ticker := time.NewTicker(d.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-d.done:
			d.disconnect()
			return
		case <-ticker.C:
			// Periodic flush if needed
		case msg := <-d.messageQueue:
			d.writeMessage(msg)
		}
	}
}

func (d *Dnstap) connect() {
	for {
		select {
		case <-d.done:
			return
		default:
		}

		conn, err := net.Dial("unix", d.socketPath)
		if err != nil {
			log.Error("Failed to connect to dnstap socket", "error", err, "path", d.socketPath)
			time.Sleep(d.reconnectDelay)
			continue
		}

		d.mu.Lock()
		d.conn = conn
		d.mu.Unlock()

		log.Info("Connected to dnstap socket", "path", d.socketPath)
		break
	}
}

func (d *Dnstap) disconnect() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.conn != nil {
		d.conn.Close()
		d.conn = nil
	}
}

func (d *Dnstap) reconnect() {
	d.disconnect()
	go d.connect()
}

func (d *Dnstap) writeMessage(msg *DnstapMessage) {
	d.mu.RLock()
	conn := d.conn
	d.mu.RUnlock()

	if conn == nil {
		return
	}

	// Simple binary encoding
	data := d.encodeMessage(msg)

	if err := d.writeFrame(conn, data); err != nil {
		log.Error("Failed to write dnstap message", "error", err)
		d.reconnect()
	}
}

func (d *Dnstap) writeFrame(conn net.Conn, data []byte) error {
	// Write frame length
	length := uint32(len(data))
	if err := binary.Write(conn, binary.BigEndian, length); err != nil {
		return err
	}

	// Write frame data
	_, err := conn.Write(data)
	return err
}

func (d *Dnstap) encodeMessage(msg *DnstapMessage) []byte {
	// Simple encoding format:
	// [1 byte type][2 bytes identity len][identity][2 bytes version len][version]
	// [16 bytes IP][2 bytes port][1 byte protocol len][protocol]
	// [8 bytes query time][4 bytes query msg len][query msg]
	// [8 bytes response time][4 bytes response msg len][response msg]

	size := 1 + 2 + len(msg.Identity) + 2 + len(msg.Version) +
		16 + 2 + 1 + len(msg.Protocol) +
		8 + 4 + len(msg.QueryMessage) +
		8 + 4 + len(msg.ResponseMsg)

	buf := make([]byte, 0, size)

	// Type
	buf = append(buf, byte(msg.Type))

	// Identity
	buf = append(buf, byte(len(msg.Identity)>>8), byte(len(msg.Identity)))
	buf = append(buf, msg.Identity...)

	// Version
	buf = append(buf, byte(len(msg.Version)>>8), byte(len(msg.Version)))
	buf = append(buf, msg.Version...)

	// IP address (16 bytes, padded if IPv4)
	ipBytes := msg.QueryAddress.To16()
	if ipBytes == nil {
		ipBytes = make([]byte, 16)
	}
	buf = append(buf, ipBytes...)

	// Port
	buf = append(buf, byte(msg.QueryPort>>8), byte(msg.QueryPort))

	// Protocol
	buf = append(buf, byte(len(msg.Protocol)))
	buf = append(buf, []byte(msg.Protocol)...)

	// Query time
	queryTimeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(queryTimeBytes, uint64(msg.QueryTime.UnixNano()))
	buf = append(buf, queryTimeBytes...)

	// Query message
	queryLen := make([]byte, 4)
	binary.BigEndian.PutUint32(queryLen, uint32(len(msg.QueryMessage)))
	buf = append(buf, queryLen...)
	buf = append(buf, msg.QueryMessage...)

	// Response time
	respTimeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(respTimeBytes, uint64(msg.ResponseTime.UnixNano()))
	buf = append(buf, respTimeBytes...)

	// Response message
	respLen := make([]byte, 4)
	binary.BigEndian.PutUint32(respLen, uint32(len(msg.ResponseMsg)))
	buf = append(buf, respLen...)
	buf = append(buf, msg.ResponseMsg...)

	return buf
}

func (d *Dnstap) logMessage(w middleware.ResponseWriter, query, response *dns.Msg, timestamp time.Time, isQuery bool) {
	msg := &DnstapMessage{
		Identity: d.identity,
		Version:  d.version,
	}

	// Set message type
	if isQuery {
		msg.Type = MessageTypeQuery
		msg.QueryTime = timestamp
	} else {
		msg.Type = MessageTypeResponse
		msg.ResponseTime = timestamp
	}

	// Set addresses
	if addr, ok := w.RemoteAddr().(*net.UDPAddr); ok {
		msg.QueryAddress = addr.IP
		msg.QueryPort = uint16(addr.Port)
		msg.Protocol = "UDP"
	} else if addr, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		msg.QueryAddress = addr.IP
		msg.QueryPort = uint16(addr.Port)
		msg.Protocol = "TCP"
	}

	// Set message data
	if query != nil {
		data, _ := query.Pack()
		msg.QueryMessage = data
	}
	if response != nil {
		data, _ := response.Pack()
		msg.ResponseMsg = data
	}

	// Send to queue
	select {
	case d.messageQueue <- msg:
	default:
		log.Warn("Dnstap message queue full, dropping message")
	}
}

// Close stops the dnstap middleware
func (d *Dnstap) Close() error {
	close(d.done)
	close(d.messageQueue)
	return nil
}

type responseWriter struct {
	middleware.ResponseWriter
	query     *dns.Msg
	queryTime time.Time
	dnstap    *Dnstap
}

func (rw *responseWriter) WriteMsg(res *dns.Msg) error {
	rw.dnstap.logMessage(rw.ResponseWriter, rw.query, res, time.Now(), false)
	return rw.ResponseWriter.WriteMsg(res)
}
