package blocklist

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/compactset"
	"github.com/semihalev/zlog/v2"
)

func (b *BlockList) runCompactRefresh(refreshRemote bool) {
	c := b.compact
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	interval := b.cfg.BlocklistRefreshInterval.Duration
	for {
		select {
		case <-timer.C:
			if err := b.refreshCompact(refreshRemote); err != nil && (c.refreshContext.Err() == nil || errors.Is(err, errCompactUncertainCommit)) {
				c.logRefreshFailure(err)
			}
			refreshRemote = true
		case <-c.refreshContext.Done():
			return
		}
		if interval <= 0 || len(b.cfg.BlockLists) == 0 {
			return
		}
		// Wait after each pass rather than queueing overlapping refreshes.
		timer.Reset(interval)
	}
}

func compactSourceID(uri string) string {
	sum := sha256.Sum256([]byte(uri))
	return fmt.Sprintf("%x", sum)
}

func (b *BlockList) refreshCompact(refreshRemote bool) error {
	c := b.compact
	c.mu.Lock()
	defer c.finishCompactBuilder()
	return b.refreshRolling(refreshRemote)
}

func (c *compactManager) logRefreshFailure(err error) {
	active, durable := c.compactPolicyAges()
	zlog.Error("Compact blocklist refresh failed", "error", err.Error(), "active_policy_age", active.String(), "last_durable_policy_age", durable.String())
}

func compactFeedError(uris []string, uri string, err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		err = compactFeedRequestError{urlErr}
	}
	var host string
	if u, parseErr := url.Parse(uri); parseErr == nil {
		host = u.Host
	}
	return fmt.Errorf("blocklists[%d] %s: %w", slices.Index(uris, uri)+1, host, err)
}

// A redirect failure can contain a complete Location, even after unwrapping
// url.Error. Only render details from known transport errors.
type compactFeedRequestError struct{ cause *url.Error }

func (e compactFeedRequestError) Error() string {
	cause := e.cause.Err
	switch {
	case errors.Is(cause, context.DeadlineExceeded):
		return context.DeadlineExceeded.Error()
	case errors.Is(cause, context.Canceled):
		return context.Canceled.Error()
	case errors.Is(cause, http.ErrSchemeMismatch):
		return http.ErrSchemeMismatch.Error()
	}
	var dnsErr *net.DNSError
	if errors.As(cause, &dnsErr) {
		if dnsErr.IsNotFound {
			return "DNS name not found"
		}
		if dnsErr.Timeout() {
			return "DNS lookup timed out"
		}
		return "DNS lookup failed"
	}
	switch err := cause.(type) {
	case syscall.Errno:
		return err.Error()
	case *net.OpError:
		var errno syscall.Errno
		if errors.As(err.Err, &errno) {
			return err.Op + ": " + errno.Error()
		}
		if err.Timeout() {
			return "network operation timed out"
		}
		return "network operation failed"
	case *tls.CertificateVerificationError, x509.HostnameError, x509.UnknownAuthorityError, x509.CertificateInvalidError:
		return "TLS certificate verification failed"
	case tls.RecordHeaderError, tls.AlertError:
		return "TLS handshake failed: " + err.Error()
	case net.Error:
		if err.Timeout() {
			return "network operation timed out"
		}
	}
	return "feed request failed"
}
func (e compactFeedRequestError) Unwrap() error { return e.cause }

func requestCompactSource(ctx context.Context, uri string, meta compactRollingSourceMetadata) (*compactFeedHTTPBody, compactRollingSourceMetadata, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, meta, err
	}
	if meta.ETag != "" {
		request.Header.Set("If-None-Match", meta.ETag)
	}
	if meta.LastModified != "" {
		request.Header.Set("If-Modified-Since", meta.LastModified)
	}
	response, body, err := doCompactFeedRequest(request)
	if err != nil {
		return nil, meta, err
	}
	tag := compactHTTPETag(response.Header.Get("ETag"))
	modified := compactHTTPLastModified(response.Header.Get("Last-Modified"))
	conditional := response.Request != nil && (response.Request.Header.Get("If-None-Match") != "" ||
		response.Request.Header.Get("If-Modified-Since") != "")
	switch {
	case response.StatusCode == http.StatusNotModified && conditional:
		if tag != "" {
			meta.ETag = tag
		}
		if modified != "" {
			meta.LastModified = modified
		}
		return nil, meta, body.Close()
	case response.StatusCode == http.StatusNotModified:
		err = fmt.Errorf("304 without a conditional request")
	case response.StatusCode != http.StatusOK:
		err = fmt.Errorf("unexpected status %d", response.StatusCode)
	case response.ContentLength > maxBlocklistBytes:
		err = fmt.Errorf("blocklist exceeds %d bytes", maxBlocklistBytes)
	default:
		meta.ETag, meta.LastModified = tag, modified
		return body, meta, nil
	}
	_ = body.Close()
	return nil, meta, err
}

// Allow two 1 KiB JSON values per owner in the checkpoint envelope.
func compactHTTPETag(value string) string {
	const limit = 1 << 10
	value = strings.Trim(value, " \t")
	tag := strings.TrimPrefix(value, "W/")
	if len(tag) < 2 || tag[0] != '"' || tag[len(tag)-1] != '"' || len(value) > limit-2 || !utf8.ValidString(value) {
		return ""
	}
	for i := 1; i < len(tag)-1; i++ {
		if b := tag[i]; b <= ' ' || b == '"' || b == 0x7f {
			return ""
		}
	}
	encoded, _ := json.Marshal(value)
	if len(encoded) > limit {
		return ""
	}
	return value
}

func compactHTTPLastModified(value string) string {
	if len(value) > 1<<10 {
		return ""
	}
	value = strings.Trim(value, " \t")
	if value == "" {
		return ""
	}
	for _, layout := range [...]string{http.TimeFormat, time.RFC850, time.ANSIC} {
		t, err := time.ParseInLocation(layout, value, time.UTC)
		if err != nil {
			continue
		}
		// Unknown zone abbreviations parse with a fabricated zero offset.
		if zone, _ := t.Zone(); zone == "GMT" || zone == "UTC" {
			return t.UTC().Format(http.TimeFormat)
		}
		break
	}
	return ""
}

// The client deadline would also run while blocklist processing is not reading the body.
// Count only Do (including redirects) and time spent inside response body reads.
func doCompactFeedRequest(request *http.Request) (*http.Response, *compactFeedHTTPBody, error) {
	client := *httpClient
	ctx, cancel := context.WithCancel(request.Context())
	request = request.WithContext(ctx)
	body := &compactFeedHTTPBody{cancel: cancel, remaining: client.Timeout}
	client.Timeout = 0
	started := time.Now()
	body.timer = time.AfterFunc(body.remaining, cancel)
	response, err := client.Do(request)
	inTime := body.stop(started)
	if err != nil {
		cancel()
		// net/http already closed any response returned with an error.
		if !inTime {
			err = context.DeadlineExceeded
		}
		return nil, nil, err
	}
	if !inTime {
		_ = response.Body.Close()
		return nil, nil, context.DeadlineExceeded
	}
	body.body = response.Body
	return response, body, nil
}

type compactFeedHTTPBody struct {
	body      io.ReadCloser
	cancel    context.CancelFunc
	timer     *time.Timer
	remaining time.Duration
}

func (b *compactFeedHTTPBody) stop(started time.Time) bool {
	b.remaining -= time.Since(started)
	if !b.timer.Stop() || b.remaining <= 0 {
		b.remaining = 0
		b.cancel()
		return false
	}
	return true
}

func (b *compactFeedHTTPBody) Read(p []byte) (int, error) {
	if b.remaining <= 0 {
		return 0, context.DeadlineExceeded
	}
	started := time.Now()
	// Only rearm a timer that stop successfully disarmed; a callback that
	// already started can never race a later read using this timer.
	b.timer.Reset(b.remaining)
	n, err := b.body.Read(p)
	if !b.stop(started) {
		err = context.DeadlineExceeded
	}
	return n, err
}

func (b *compactFeedHTTPBody) Close() error {
	b.cancel()
	return b.body.Close()
}

type compactFeedReader struct {
	r   io.Reader
	ctx context.Context
}

func (r compactFeedReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

// Fail the pipe before EOF on an invalid, truncated
// or oversized transfer. The builder never accepts a partial inventory.
func (c *compactManager) emitRollingResponse(out io.Writer, body io.Reader) error {
	limited := &io.LimitedReader{R: body, N: maxBlocklistBytes + 1}
	input := compactFeedReader{r: limited, ctx: c.refreshContext}
	writer := bufio.NewWriterSize(out, 256<<10) // covered by compactStreamMemory
	err := scanRollingHosts(input, writer, false)
	if limited.N == 0 {
		return fmt.Errorf("blocklist exceeds %d bytes", maxBlocklistBytes)
	}
	if err != nil {
		return err
	}
	if err = writer.Flush(); err != nil {
		return err
	}
	return c.refreshContext.Err()
}

func scanRollingHosts(input io.Reader, out *bufio.Writer, local bool) error {
	sc := bufio.NewScanner(input)
	for sc.Scan() {
		line, _, _ := bytes.Cut(sc.Bytes(), []byte{'#'})
		if len(line) == 0 {
			continue
		}
		if !local {
			if done, err := writeRollingPlainName(out, line); err != nil {
				return err
			} else if done {
				continue
			}
		}
		var first []byte
		hosts := false
		for field := range bytes.FieldsSeq(line) {
			if first == nil {
				first = field
				continue
			}
			if !local && !hosts {
				if _, err := netip.ParseAddr(string(first)); err != nil {
					return fmt.Errorf("feed hosts row has no address: %q", first)
				}
			}
			hosts = true
			if err := emitRollingName(out, field, local); err != nil {
				return err
			}
		}
		if !hosts && first != nil {
			if err := emitRollingName(out, first, local); err != nil {
				return err
			}
		}
	}
	return sc.Err()
}

func emitRollingName(out *bufio.Writer, field []byte, local bool) error {
	if !local {
		if done, err := writeRollingPlainName(out, field); done || err != nil {
			return err
		}
	}
	if !utf8.Valid(field) {
		return fmt.Errorf("invalid UTF-8 in DNS name %q", field)
	}
	name := string(field)
	if !local {
		if _, ok := dns.IsDomainName(name); !ok {
			return fmt.Errorf("invalid feed DNS name %q", name)
		}
	}
	key := dns.CanonicalName(name)
	if local {
		if len(key) > compactset.MaxKey {
			return fmt.Errorf("canonical DNS name exceeds %d bytes", compactset.MaxKey)
		}
	} else if !dns.IsFqdn(key) {
		return fmt.Errorf("noncanonical feed DNS name %q", key)
	}
	if _, err := out.WriteString(key); err != nil {
		return err
	}
	return out.WriteByte('\n')
}

// Check for a single plain ASCII name and lowercase it directly into the
// buffered writer. Hosts rows, escapes and non-ASCII use the full parser.
func writeRollingPlainName(out *bufio.Writer, field []byte) (bool, error) {
	const dnsPresentationLimit = 256 // dns.IsDomainName's unescaped wire-length limit
	if len(field) > dnsPresentationLimit {
		return false, nil
	}
	if out.Available() < len(field)+2 {
		if err := out.Flush(); err != nil {
			return false, err
		}
	}
	record := out.AvailableBuffer()[:len(field)]
	label := 0
	for i, ch := range field {
		switch {
		case ch == '\\' || ch >= 0x80 || ch == ' ' || ch >= '\t' && ch <= '\r':
			return false, nil
		case ch == '.':
			if label == 0 && len(field) != 1 {
				return false, nil
			}
			label = 0
		default:
			label++
			if label == 64 {
				return false, nil
			}
			if ch >= 'A' && ch <= 'Z' {
				ch += 'a' - 'A'
			}
		}
		record[i] = ch
	}
	if label != 0 {
		if len(field) == dnsPresentationLimit {
			return false, nil
		}
		record = append(record, '.')
	}
	_, err := out.Write(append(record, '\n'))
	return true, err
}

const compactLocalEmitBuffer = 64 << 10 // covered by compactStreamMemory

func (b *BlockList) emitRollingLocal(ctx context.Context, out io.Writer, ledger *compactFeedLedger, fingerprint string) error {
	h := sha256.New()
	writer := bufio.NewWriterSize(out, compactLocalEmitBuffer)
	err := walkCompactFeedLocal(ctx, b.cfg.BlockListDir, b.compact.dir, ledger, func(path string, f *os.File, info os.FileInfo) error {
		frameCompactLocalFile(h, path, info.Size())
		return scanRollingHosts(compactFeedReader{r: io.TeeReader(f, h), ctx: ctx}, writer, true)
	})
	if err != nil {
		return err
	}
	if fmt.Sprintf("%x", h.Sum(nil)) != fingerprint {
		return fmt.Errorf("local blocklist files changed during compact replacement")
	}
	return writer.Flush()
}

// Preserve filepath.Walk's lexical traversal for the local feed
// fingerprint, without loading an unbounded directory listing. The fixed
// read batch and file-read buffers belong to compactStreamMemory; retained
// directory entries and paths are charged before growth.
func walkCompactFeedLocal(ctx context.Context, dir, state string, l *compactFeedLedger, visit func(string, *os.File, os.FileInfo) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Follow the configured root. Inside it, follow symlinks only to files.
	root, info, stateInfo, err := config.ResolveCompactBlocklistRoots(state, dir, true)
	if err != nil {
		return fmt.Errorf("local blocklist directory %q: %w", dir, err)
	}
	if root == "" {
		return nil
	}
	var rootPrefix string
	if root != dir && root != "." {
		rootPrefix = root
		if !os.IsPathSeparator(root[len(root)-1]) {
			rootPrefix += string(os.PathSeparator)
		}
	}
	var walk func(string, os.FileInfo) error
	walk = func(path string, info os.FileInfo) error {
		if !info.IsDir() {
			target := path
			if info.Mode()&os.ModeSymlink != 0 {
				var err error
				target, err = filepath.EvalSymlinks(path)
				if err != nil {
					return err
				}
				info, err = os.Stat(target)
				if err != nil {
					return err
				}
			}
			if !info.Mode().IsRegular() {
				return nil
			}
			// Keep the logical path in the fingerprint as in earlier checkpoints.
			logical := path
			if root != dir {
				logical = filepath.Join(dir, path[len(rootPrefix):])
			}
			f, st, err := openCompactLocalFile(target)
			if err != nil || f == nil {
				return err
			}
			err = visit(logical, f, st)
			if closeErr := f.Close(); err == nil {
				err = closeErr
			}
			if err != nil {
				return fmt.Errorf("read local blocklist %q: %w", path, err)
			}
			return nil
		}
		used := l.used
		defer func() { l.used = used }()
		names, err := compactFeedLocalNames(ctx, path, l, stateInfo)
		if err != nil {
			return err
		}
		for _, name := range names {
			if err := ctx.Err(); err != nil {
				return err
			}
			cost := len(path) + 1 + compactFeedKeyCost(name)
			if err := l.reserve(cost); err != nil {
				return err
			}
			child := filepath.Join(path, name)
			info, err := os.Lstat(child)
			if err == nil {
				err = walk(child, info)
			}
			l.used -= cost
			if err != nil {
				return err
			}
		}
		return nil
	}
	return walk(root, info)
}

func compactFeedLocalNames(ctx context.Context, path string, l *compactFeedLedger, state os.FileInfo) (names []string, err error) {
	f, err := openCompactFeedDirectory(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
	}()
	if info, err := f.Stat(); err != nil {
		return nil, err
	} else if os.SameFile(info, state) {
		return nil, fmt.Errorf("local blocklist directory %q is the compact state directory", path)
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		batch, readErr := f.Readdirnames(32)
		if readErr != nil && readErr != io.EOF {
			return nil, readErr
		}
		for _, name := range batch {
			if err := l.reserve(compactFeedKeyCost(name)); err != nil {
				return nil, err
			}
			names = append(names, name)
		}
		if readErr == io.EOF {
			slices.Sort(names)
			return names, nil
		}
	}
}

func (b *BlockList) compactLocalFingerprint(l *compactFeedLedger) (string, error) {
	ctx := b.compact.refreshContext
	h := sha256.New()
	var buf [32 << 10]byte
	err := walkCompactFeedLocal(ctx, b.cfg.BlockListDir, b.compact.dir, l, func(path string, f *os.File, info os.FileInfo) error {
		frameCompactLocalFile(h, path, info.Size())
		return copyCompactFingerprint(ctx, h, f, buf[:])
	})
	if err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func frameCompactLocalFile(h io.Writer, path string, size int64) {
	fmt.Fprintf(h, "%d:%s:%d:", len(path), path, size)
}

func copyCompactFingerprint(ctx context.Context, dst io.Writer, src io.Reader, buf []byte) error {
	_, err := io.CopyBuffer(dst, compactFeedReader{r: src, ctx: ctx}, buf)
	return err
}
