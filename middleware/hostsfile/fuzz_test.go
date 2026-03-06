package hostsfile

import (
	"net"
	"testing"
)

// FuzzParseLine fuzzes hosts file line parsing
func FuzzParseLine(f *testing.F) {
	// Add seed corpus with various hosts file formats
	f.Add("127.0.0.1 localhost")
	f.Add("127.0.0.1 localhost localhost.localdomain")
	f.Add("192.168.1.1 myhost # this is a comment")
	f.Add("::1 localhost ip6-localhost")
	f.Add("fe80::1%eth0 link-local")
	f.Add("# This is a comment line")
	f.Add("")
	f.Add("   ")
	f.Add("invalid-ip hostname")
	f.Add("256.256.256.256 invalid")
	f.Add("192.168.1.1")                                       // IP only, no hostname
	f.Add("2001:db8::1 ipv6host")                              // IPv6
	f.Add("0.0.0.0 blocked.domain.com")                        // Null route
	f.Add("127.0.0.1 host1 host2 host3 host4 host5")           // Multiple aliases
	f.Add("*.example.com wildcard")                            // Invalid (IP should be first)
	f.Add("192.168.1.1 *.example.com")                         // Wildcard hostname
	f.Add("\t192.168.1.1\tlocalhost\t# tabbed")                // Tabs
	f.Add("192.168.1.1    localhost   alias   # extra spaces") // Extra spaces
	f.Add("192.168.1.1 UPPERCASE.DOMAIN.COM")                  // Uppercase
	f.Add("192.168.1.1 xn--nxasmq5b.com")                      // IDN/punycode
	f.Add("192.168.1.1 host-with-dashes.example.com")          // Dashes
	f.Add("192.168.1.1 host_with_underscores.example.com")     // Underscores
	f.Add("192.168.1.1 123numeric.com")                        // Starts with number
	f.Add("fe80::1%lo0 link-local-with-zone")                  // IPv6 with zone
	f.Add("::ffff:192.168.1.1 ipv4-mapped")                    // IPv4-mapped IPv6
	f.Add("192.168.1.1 a")                                     // Single char hostname
	f.Add("192.168.1.1 " + string(make([]byte, 1000)))         // Very long line

	f.Fuzz(func(t *testing.T, line string) {
		// This should not panic regardless of input
		_, _, _ = parseLine(line)
	})
}

// FuzzMatchWildcard fuzzes wildcard pattern matching
func FuzzMatchWildcard(f *testing.F) {
	f.Add("*.example.com", "sub.example.com")
	f.Add("*.example.com", "example.com")
	f.Add("*.example.com", "a.b.example.com")
	f.Add("*.com", "example.com")
	f.Add("*", "anything")
	f.Add("", "test")
	f.Add("*.example.com", "")
	f.Add("notawildcard.com", "notawildcard.com")
	f.Add("*.*.example.com", "a.b.example.com") // Double wildcard (invalid but shouldn't panic)

	f.Fuzz(func(t *testing.T, pattern, name string) {
		// This should not panic regardless of input
		_ = matchWildcard(pattern, name)
	})
}

// FuzzHostsDBLookup fuzzes the hosts database lookup operations
func FuzzHostsDBLookup(f *testing.F) {
	f.Add("localhost")
	f.Add("localhost.")
	f.Add("LOCALHOST")
	f.Add("")
	f.Add(".")
	f.Add("nonexistent.domain.com")
	f.Add("sub.example.com")

	f.Fuzz(func(t *testing.T, name string) {
		db := &HostsDB{
			hosts:   make(map[string]*HostEntry),
			reverse: make(map[string][]string),
		}

		// Add some test entries
		db.hosts["localhost"] = &HostEntry{
			Name: "localhost",
			IPv4: []net.IP{net.IPv4(127, 0, 0, 1)},
		}

		// Create minimal Hostsfile for testing
		h := &Hostsfile{
			ttl: 600,
		}
		h.db.Store(db)

		// These should not panic regardless of input
		_, _ = h.lookupA(db, name)
		_, _ = h.lookupAAAA(db, name)
		_ = h.hostExists(db, name)
	})
}
