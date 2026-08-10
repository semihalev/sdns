package accesslog

import (
	"context"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/zlog/v2"
)

// Log type.
type Log struct {
	cfg     *config.Config
	logFile *os.File
}

// New returns a new access log middleware.
func New(cfg *config.Config) *Log {
	var logFile *os.File
	var err error

	if cfg.AccessLog != "" {
		logFile, err = os.OpenFile(cfg.AccessLog, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
		if err != nil {
			zlog.Error("Access log file open failed", "error", strings.Trim(err.Error(), "\n"))
		}
	}

	return &Log{
		cfg:     cfg,
		logFile: logFile,
	}
}

// (*Log).Name returns the middleware name.
func (a *Log) Name() string { return name }

// (*Log).ClientOnly marks accesslog as a client-traffic
// observer; middleware.Setup excludes it from internal
// sub-pipelines so access logs reflect real client queries only.
func (a *Log) ClientOnly() bool { return true }

// (*Log).ServeDNS implements the Handle interface.
func (a *Log) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	ch.Next(ctx)

	w := ch.Writer

	if a.logFile != nil && w.Written() && !w.Internal() && len(ch.Request.Question) > 0 {
		// Read the log's facts from the request and the writer rather than
		// from a parsed response: a response served as bytes would have to
		// be decoded just to be logged, and a message decoded from bytes
		// reports an inflated length because Unpack does not restore
		// Compress. A reply's CD is the request's (RFC 1035 §4.1.1), and
		// its question is the one asked.
		cd := "-cd"
		if ch.Request.CheckingDisabled {
			cd = "+cd"
		}

		record := []string{
			w.RemoteIP().String() + " -",
			"[" + time.Now().Format("02/Jan/2006:15:04:05 -0700") + "]",
			formatQuestion(ch.Request.Question[0]),
			w.Proto(),
			cd,
			dns.RcodeToString[w.Rcode()],
			strconv.Itoa(middleware.ResponseSize(w)),
		}

		_, err := a.logFile.WriteString(strings.Join(record, " ") + "\n")
		if err != nil {
			zlog.Error("Access log write failed", "error", strings.Trim(err.Error(), "\n"))
		}
	}
}

func formatQuestion(q dns.Question) string {
	return "\"" + strings.ToLower(q.Name) + " " + dns.ClassToString[q.Qclass] + " " + dns.TypeToString[q.Qtype] + "\""
}

const name = "accesslog"
