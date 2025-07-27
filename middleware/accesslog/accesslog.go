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

// AccessLog type.
type AccessLog struct {
	cfg     *config.Config
	logFile *os.File
}

// New returns a new AccessLog.
func New(cfg *config.Config) *AccessLog {
	var logFile *os.File
	var err error

	if cfg.AccessLog != "" {
		logFile, err = os.OpenFile(cfg.AccessLog, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
		if err != nil {
			zlog.Error("Access log file open failed", "error", strings.Trim(err.Error(), "\n"))
		}
	}

	return &AccessLog{
		cfg:     cfg,
		logFile: logFile,
	}
}

// (*AccessLog).Name name return middleware name.
func (a *AccessLog) Name() string { return name }

// (*AccessLog).ServeDNS serveDNS implements the Handle interface.
func (a *AccessLog) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	ch.Next(ctx)

	w := ch.Writer

	if a.logFile != nil && w.Written() && !w.Internal() {
		resp := w.Msg()

		cd := "-cd"
		if resp.CheckingDisabled {
			cd = "+cd"
		}

		record := []string{
			w.RemoteIP().String() + " -",
			"[" + time.Now().Format("02/Jan/2006:15:04:05 -0700") + "]",
			formatQuestion(resp.Question[0]),
			w.Proto(),
			cd,
			dns.RcodeToString[resp.Rcode],
			strconv.Itoa(resp.Len()),
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
