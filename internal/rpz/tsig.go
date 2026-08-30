package rpz

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// TSIGKey is a transfer-signing key as the config spells it:
// "name:algorithm:base64-secret". It lives in the engine so the config
// gate judges the spelling with exactly the parser the feed loop uses.
type TSIGKey struct {
	Name      string
	Algorithm string
	Secret    string
}

// ParseTSIGKey reads the config spelling. Name and algorithm come back
// canonical (rooted), as every dns-level TSIG API expects them.
func ParseTSIGKey(s string) (*TSIGKey, error) {
	if s == "" {
		return nil, nil
	}
	parts := strings.SplitN(s, ":", 3)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, errors.New(`tsig_key must be "name:algorithm:base64-secret"`)
	}
	if _, err := base64.StdEncoding.DecodeString(parts[2]); err != nil {
		return nil, fmt.Errorf("tsig_key secret is not base64: %w", err)
	}
	return &TSIGKey{
		Name:      dns.CanonicalName(parts[0]),
		Algorithm: dns.CanonicalName(parts[1]),
		Secret:    parts[2],
	}, nil
}
