package config

import (
	"fmt"
	"strings"
)

// Addrs is where a listener listens: one "host:port", as sdns configurations
// have always written it, or a list of them.
//
//	bind = ":53"
//	bind = ["192.0.2.53:53", "[2001:db8::53]:53"]
//
// An empty string or an empty list is no address at all.
type Addrs []string

// UnmarshalTOML accepts a single address or an array of them.
func (a *Addrs) UnmarshalTOML(v any) error {
	switch v := v.(type) {
	case string:
		*a = nil
		if v != "" {
			*a = Addrs{v}
		}
		return nil
	case []any:
		out := make(Addrs, 0, len(v))
		for _, e := range v {
			s, ok := e.(string)
			if !ok {
				return fmt.Errorf("an address list holds host:port strings, not %T", e)
			}
			out = append(out, s)
		}
		*a = out
		return nil
	default:
		return fmt.Errorf("an address is a host:port string or a list of them, not %T", v)
	}
}

// String joins the addresses for a log line.
func (a Addrs) String() string { return strings.Join(a, ", ") }
