package resolver

// The DNS transport (Conn, wire framing, buffer pool and the
// question-section guard) lives in internal/dnsclient. The resolver
// keeps its own connection/buffer pooling, circuit breaker, RTT
// tracking and retry policy on top of these primitives, so it consumes
// them through these aliases rather than owning the transport code.

import "github.com/semihalev/sdns/internal/dnsclient"

// Conn is the resolver's DNS connection type. It is an alias for
// dnsclient.Conn so existing resolver call sites (utils.go pooling,
// resolver.exchange) and tests continue to use the unqualified name.
type Conn = dnsclient.Conn

// ErrQuestion is returned by (*Conn).Exchange when the response's
// question section does not match the outstanding request (issue #469).
var ErrQuestion = dnsclient.ErrQuestion

// AcquireBuf and ReleaseBuf expose the shared size-bucketed buffer pool.
var (
	AcquireBuf = dnsclient.AcquireBuf
	ReleaseBuf = dnsclient.ReleaseBuf
)
