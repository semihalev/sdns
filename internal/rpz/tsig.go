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
	// The name travels in every signed request; one that cannot be
	// packed would pass here and then fail the first transfer.
	if _, ok := dns.IsDomainName(parts[0]); !ok {
		return nil, fmt.Errorf("tsig_key name %q is not a valid domain name", parts[0])
	}
	algo := dns.CanonicalName(parts[1])
	// Only the HMACs the dns library can actually sign with: anything
	// else would pass `sdns -t` and then fail every transfer at runtime,
	// leaving a permanently empty, fail-open zone behind a config the
	// gate called healthy.
	switch algo {
	case dns.HmacSHA1, dns.HmacSHA224, dns.HmacSHA256, dns.HmacSHA384, dns.HmacSHA512:
	default:
		return nil, fmt.Errorf("tsig_key algorithm %q is not supported; use one of hmac-sha1, hmac-sha224, hmac-sha256, hmac-sha384, hmac-sha512", algo)
	}
	return &TSIGKey{
		Name:      dns.CanonicalName(parts[0]),
		Algorithm: algo,
		Secret:    parts[2],
	}, nil
}
