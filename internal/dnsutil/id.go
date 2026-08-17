package dnsutil

import (
	randv2 "math/rand/v2"

	"github.com/miekg/dns"
)

// init replaces miekg's message-ID generator, a documented extension point
// ("This being a variable the function can be reassigned"). The default
// reads two bytes from crypto/rand through binary.Read, whose scratch
// buffer escapes — one heap allocation per upstream attempt and per
// SetQuestion, process-wide.
//
// math/rand/v2's global generator is the runtime's ChaCha8 stream:
// cryptographically seeded from OS entropy, unseedable, per-M and
// lock-free. Go 1.22 introduced it precisely so that security-sensitive
// uses of math/rand stay safe, and message IDs are exactly that — an
// off-path attacker must not predict them (RFC 5452). Unpredictability is
// preserved; the allocation is not.
func init() {
	dns.Id = func() uint16 { return uint16(randv2.Uint32()) } //nolint:gosec // G404 - the v2 global IS the runtime's ChaCha8 CSPRNG; deliberate, see above
}
