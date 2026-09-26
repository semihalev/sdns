// Command doqload is the DNS-over-QUIC load generator for
// contrib/bench/resolver_bench.py, which drives it in place of dnsperf
// (which has no DoQ mode) and parses its summary the same way.
//
// It opens -c connections and runs -t concurrent streams on each for -l
// seconds, one query per stream as RFC 9250 frames it (message ID 0, FIN
// after the query), cycling through the corpus. The summary lines match
// dnsperf's wording so the harness reads both alike.
//
// Build it for the machine the load runs on, beside the harness:
//
//	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o doqload ./contrib/bench/doqload
//
// Run on its own, 16 connections of 32 streams for 20 seconds:
//
//	doqload -s 127.0.0.1:5393 -d hits.txt -c 16 -t 32 -l 20
//
// The certificate is not verified: this is a load generator for a local
// instance, not a client.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

func main() {
	addr := flag.String("s", "127.0.0.1:853", "DoQ server address")
	corpus := flag.String("d", "", "corpus file, one name per line")
	conns := flag.Int("c", 4, "connections")
	streams := flag.Int("t", 16, "concurrent streams per connection")
	seconds := flag.Int("l", 10, "run length in seconds")
	flag.Parse()

	queries, err := loadCorpus(*corpus)
	if err != nil {
		fmt.Fprintln(os.Stderr, "doqload:", err)
		os.Exit(1)
	}

	var cs []*quic.Conn
	for range *conns {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		c, err := quic.DialAddr(ctx, *addr,
			&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"doq"}}, //nolint:gosec // a load generator for a local instance
			&quic.Config{MaxIdleTimeout: 30 * time.Second, KeepAlivePeriod: 5 * time.Second})
		cancel()
		if err != nil {
			fmt.Fprintln(os.Stderr, "doqload: dial:", err)
			os.Exit(1)
		}
		cs = append(cs, c)
	}

	var sent, done atomic.Int64
	var latencyNs atomic.Int64
	deadline := time.Now().Add(time.Duration(*seconds) * time.Second)
	start := time.Now()
	var wg sync.WaitGroup
	for ci, c := range cs {
		for si := range *streams {
			wg.Add(1)
			go func(c *quic.Conn, next int) {
				defer wg.Done()
				buf := make([]byte, dns.MaxMsgSize)
				for time.Now().Before(deadline) {
					q := queries[next%len(queries)]
					next++
					sent.Add(1)
					t := time.Now()
					if exchange(c, q, buf) {
						latencyNs.Add(int64(time.Since(t)))
						done.Add(1)
					}
				}
			}(c, ci*(*streams)+si)
		}
	}
	wg.Wait()
	elapsed := time.Since(start).Seconds()
	for _, c := range cs {
		_ = c.CloseWithError(0, "")
	}

	d := done.Load()
	avg := 0.0
	if d > 0 {
		avg = float64(latencyNs.Load()) / float64(d) / 1e9
	}
	fmt.Printf("  Queries sent:         %d\n", sent.Load())
	fmt.Printf("  Queries completed:    %d\n", d)
	fmt.Printf("  Queries per second:   %f\n", float64(d)/elapsed)
	fmt.Printf("  Average Latency (s):  %f\n", avg)
}

// exchange sends one framed query on a fresh stream and reads the framed
// reply whole.
func exchange(c *quic.Conn, query, buf []byte) bool {
	s, err := c.OpenStreamSync(context.Background())
	if err != nil {
		return false
	}
	_ = s.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := s.Write(query); err != nil {
		return false
	}
	_ = s.Close()
	if _, err := io.ReadFull(s, buf[:2]); err != nil {
		return false
	}
	n := int(binary.BigEndian.Uint16(buf))
	_, err = io.ReadFull(s, buf[:n])
	return err == nil && n >= 12
}

// loadCorpus frames one A query per corpus name, the shape dnsperf sends:
// RD set, no EDNS, message ID 0 as DoQ requires.
func loadCorpus(path string) ([][]byte, error) {
	f, err := os.Open(path) //nolint:gosec // G304 - the operator names the corpus on the command line
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out [][]byte
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 {
			continue
		}
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(fields[0]), dns.TypeA)
		m.Id = 0
		raw, err := m.Pack()
		if err != nil {
			continue
		}
		out = append(out, append(binary.BigEndian.AppendUint16(nil, uint16(len(raw))), raw...)) //nolint:gosec // a query is small
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no usable names in %s", path)
	}
	return out, sc.Err()
}
