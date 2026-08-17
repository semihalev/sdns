package dnstap

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/zlog/v2"
)

// MessageType represents dnstap message types.
type MessageType uint32

const (
	MessageTypeQuery    MessageType = 1
	MessageTypeResponse MessageType = 2
)

// DnstapMessage represents a simplified dnstap message.
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

// Dnstap middleware for binary DNS logging.
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

// New creates a new dnstap middleware.
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

// (*Dnstap).Name name returns the name of the middleware.
func (d *Dnstap) Name() string {
	return "dnstap"
}

// (*Dnstap).ClientOnly marks dnstap as a client-traffic observer;
// middleware.Setup excludes it from internal sub-pipelines so
// dnstap streams reflect real client queries only.
func (d *Dnstap) ClientOnly() bool { return true }

// (*Dnstap).OncePerQuery: the query frame is emitted at entry, so the
// serve replay after an inline handoff must not tap the query twice.
func (d *Dnstap) OncePerQuery() bool { return true }

// (*Dnstap).ServeDNS serveDNS logs DNS messages in dnstap format.
// Disconnected dnstap is a read-lock check and a wire-born request passes
// undecoded; a connected tap packs the request and materializes (enabling
// it is documented as disabling the zero guarantee).
func (d *Dnstap) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	if !d.isEnabled() {
		ch.Next(ctx)
		return
	}

	ctx, req := ch.Materialize(ctx)
	if req == nil {
		return
	}
	w := ch.Writer

	// Capture query time
	queryTime := time.Now()

	// Log query if enabled
	if d.logQueries {
		d.logMessage(w, req, nil, queryTime, true)
	}

	// Create response writer wrapper to capture response.
	// Chains are pooled and reused across requests, so the wrapper
	// must be removed before returning — otherwise a later request
	// picks up a stale dnstap wrapper and duplicates response logs
	// for a query it never observed.
	if d.logResponses {
		orig := ch.Writer
		ch.Writer = &responseWriter{
			ResponseWriter: w,
			query:          req,
			queryTime:      queryTime,
			dnstap:         d,
		}
		defer func() { ch.Writer = orig }()
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
			zlog.Error("Failed to connect to dnstap socket", "error", err, "path", d.socketPath)
			time.Sleep(d.reconnectDelay)
			continue
		}

		d.mu.Lock()
		d.conn = conn
		d.mu.Unlock()

		zlog.Info("Connected to dnstap socket", "path", d.socketPath)
		break
	}
}

func (d *Dnstap) disconnect() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.conn != nil {
		_ = d.conn.Close() //nolint:gosec // G104 - closing best effort
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
		zlog.Error("Failed to write dnstap message", "error", err)
		d.reconnect()
	}
}

func (d *Dnstap) writeFrame(conn net.Conn, data []byte) error {
	// Write frame length
	length := uint32(len(data)) //nolint:gosec // G115 - DNS message size is bounded
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
	buf = append(buf, byte(msg.Type&0xFF)) //nolint:gosec // intentional truncation to byte

	// Identity
	buf = append(buf, byte(len(msg.Identity)>>8), byte(len(msg.Identity)&0xFF)) //nolint:gosec // intentional big-endian encoding
	buf = append(buf, msg.Identity...)

	// Version
	buf = append(buf, byte(len(msg.Version)>>8), byte(len(msg.Version)&0xFF)) //nolint:gosec // intentional big-endian encoding
	buf = append(buf, msg.Version...)

	// IP address (16 bytes, padded if IPv4)
	ipBytes := msg.QueryAddress.To16()
	if ipBytes == nil {
		ipBytes = make([]byte, 16)
	}
	buf = append(buf, ipBytes...)

	// Port
	buf = append(buf, byte(msg.QueryPort>>8), byte(msg.QueryPort&0xFF)) //nolint:gosec // intentional uint16 byte extraction

	// Protocol
	buf = append(buf, byte(len(msg.Protocol)&0xFF)) //nolint:gosec // intentional truncation to byte
	buf = append(buf, []byte(msg.Protocol)...)

	// Query time
	queryTimeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(queryTimeBytes, uint64(msg.QueryTime.UnixNano())) //nolint:gosec // G115 - time conversion
	buf = append(buf, queryTimeBytes...)

	// Query message
	queryLen := make([]byte, 4)
	binary.BigEndian.PutUint32(queryLen, uint32(len(msg.QueryMessage))) //nolint:gosec // G115 - DNS message size is bounded
	buf = append(buf, queryLen...)
	buf = append(buf, msg.QueryMessage...)

	// Response time
	respTimeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(respTimeBytes, uint64(msg.ResponseTime.UnixNano())) //nolint:gosec // G115 - time conversion
	buf = append(buf, respTimeBytes...)

	// Response message
	respLen := make([]byte, 4)
	binary.BigEndian.PutUint32(respLen, uint32(len(msg.ResponseMsg))) //nolint:gosec // G115 - DNS message size is bounded
	buf = append(buf, respLen...)
	buf = append(buf, msg.ResponseMsg...)

	return buf
}

func (d *Dnstap) logMessage(w middleware.ResponseWriter, query, response *dns.Msg, timestamp time.Time, isQuery bool) {
	msg := d.newTapMessage(w, timestamp, isQuery)

	// Set message data
	if query != nil {
		data, _ := query.Pack()
		msg.QueryMessage = data
	}
	if response != nil {
		data, _ := response.Pack()
		msg.ResponseMsg = data
	}

	d.enqueue(msg)
}

// prepareWireTap is logMessage's assembly for a response that already exists
// as wire bytes: the tap keeps an owned copy of them instead of packing the
// message a second time. The body is borrowed pooled storage, valid only for
// this call, and the queue is asynchronous — the copy is not an optimization
// choice but the ownership rule.
//
// It prepares without enqueueing, because whether this response was actually
// served as bytes is the downstream's answer, and the caller only has it
// after the write.
func (d *Dnstap) prepareWireTap(
	w middleware.ResponseWriter,
	query *dns.Msg,
	body []byte,
	timestamp time.Time,
) *DnstapMessage {
	msg := d.newTapMessage(w, timestamp, false)

	if query != nil {
		data, _ := query.Pack()
		msg.QueryMessage = data
	}
	msg.ResponseMsg = append([]byte(nil), body...)
	return msg
}

func (d *Dnstap) newTapMessage(w middleware.ResponseWriter, timestamp time.Time, isQuery bool) *DnstapMessage {
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

	// Set addresses. The IP is copied, never aliased: an owned transport
	// keeps the client's address in its job slab and rewrites it for the
	// next packet, while this message travels to a queue another goroutine
	// drains later. Sharing the slice would log one client's query against
	// another's address, and race with the rewrite while doing it.
	if addr, ok := w.RemoteAddr().(*net.UDPAddr); ok {
		msg.QueryAddress = append(net.IP(nil), addr.IP...)
		msg.QueryPort = uint16(addr.Port) //nolint:gosec // G115 - port is 0-65535
		msg.Protocol = "UDP"
	} else if addr, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		msg.QueryAddress = append(net.IP(nil), addr.IP...)
		msg.QueryPort = uint16(addr.Port) //nolint:gosec // G115 - port is 0-65535
		msg.Protocol = "TCP"
	}
	return msg
}

func (d *Dnstap) enqueue(msg *DnstapMessage) {
	select {
	case d.messageQueue <- msg:
	default:
		zlog.Warn("Dnstap message queue full, dropping message")
	}
}

// (*Dnstap).Close close stops the dnstap middleware.
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

// Size forwards the response's wire length from the writer beneath. The
// embedded interface deliberately does not carry Size, so a wrapper has to
// pass it along or observers above fall back to decoding the response.
func (w *responseWriter) Size() int {
	return middleware.ResponseSize(w.ResponseWriter)
}

func (rw *responseWriter) WriteMsg(res *dns.Msg) error {
	rw.dnstap.logMessage(rw.ResponseWriter, rw.query, res, time.Now(), false)
	return rw.ResponseWriter.WriteMsg(res)
}

// WireReady passes the byte path through: this layer only observes
// responses, so its presence must not push a cache hit back onto the Msg
// path — which is what wrapping without these two methods did.
// BeginWire/CommitWire/AbortWire pass the body lease through; the commit
// flows through WriteWire so the tap still observes (and copies) the body.
func (rw *responseWriter) BeginWire(size, reserve int) []byte {
	if leaser, ok := rw.ResponseWriter.(middleware.WireBodyLeaser); ok {
		return leaser.BeginWire(size, reserve)
	}
	return nil
}

func (rw *responseWriter) CommitWire(body []byte, info middleware.WireInfo) error {
	return rw.WriteWire(body, info)
}

func (rw *responseWriter) AbortWire() {
	if leaser, ok := rw.ResponseWriter.(middleware.WireBodyLeaser); ok {
		leaser.AbortWire()
	}
}

func (rw *responseWriter) WireReady() (middleware.WireCapability, bool) {
	next, ok := rw.ResponseWriter.(middleware.WireWriter)
	if !ok {
		return middleware.WireCapability{}, false
	}
	return next.WireReady()
}

// WriteWire taps the response and forwards the bytes. The tap is prepared
// before the downstream write — the body is borrowed and valid only for
// this call — but committed after it, and only if the chain did not decline:
// on ErrWireFallback the cache retakes the Msg path and WriteMsg taps that
// serve, so enqueueing here would log the same response twice. A terminal
// transport error still commits — the response left, or partially left, the
// process, which is exactly what a tap records.
func (rw *responseWriter) WriteWire(body []byte, info middleware.WireInfo) error {
	next, ok := rw.ResponseWriter.(middleware.WireWriter)
	if !ok {
		return middleware.ErrWireFallback
	}
	tap := rw.dnstap.prepareWireTap(rw.ResponseWriter, rw.query, body, time.Now())
	err := next.WriteWire(body, info)
	if !errors.Is(err, middleware.ErrWireFallback) {
		rw.dnstap.enqueue(tap)
	}
	return err
}
