package config

import "testing"

func TestSplitDoTUpstream(t *testing.T) {
	for _, tc := range []struct {
		in       string
		addr     string
		authName string
		ok       bool
	}{
		{"192.0.2.1:853", "192.0.2.1:853", "", true},
		{"9.9.9.9:853#dns.quad9.net", "9.9.9.9:853", "dns.quad9.net", true},
		{"[2620:fe::fe]:853#dns.quad9.net", "[2620:fe::fe]:853", "dns.quad9.net", true},
		// The root's dot is dropped: TLS names carry none.
		{"9.9.9.9:853#dns.quad9.net.", "9.9.9.9:853", "dns.quad9.net", true},
		{"9.9.9.9:853#Dns-1.Example.COM", "9.9.9.9:853", "Dns-1.Example.COM", true},
		{"9.9.9.9:853#localhost", "9.9.9.9:853", "localhost", true},

		{"9.9.9.9:853#", "9.9.9.9:853", "", false},
		{"9.9.9.9:853#.", "9.9.9.9:853", "", false},
		{"9.9.9.9:853#9.9.9.9", "9.9.9.9:853", "9.9.9.9", false},
		{"9.9.9.9:853#2620:fe::fe", "9.9.9.9:853", "2620:fe::fe", false},
		{"9.9.9.9:853#dns..quad9.net", "9.9.9.9:853", "dns..quad9.net", false},
		{"9.9.9.9:853#-dns.quad9.net", "9.9.9.9:853", "-dns.quad9.net", false},
		{"9.9.9.9:853#dns-.quad9.net", "9.9.9.9:853", "dns-.quad9.net", false},
		{"9.9.9.9:853#dns_quad9.net", "9.9.9.9:853", "dns_quad9.net", false},
		{"9.9.9.9:853#*.quad9.net", "9.9.9.9:853", "*.quad9.net", false},
		{"9.9.9.9:853#dns.quad9.net#x", "9.9.9.9:853", "dns.quad9.net#x", false},
	} {
		addr, authName, ok := SplitDoTUpstream(tc.in)
		if addr != tc.addr || authName != tc.authName || ok != tc.ok {
			t.Errorf("SplitDoTUpstream(%q) = %q, %q, %v; want %q, %q, %v",
				tc.in, addr, authName, ok, tc.addr, tc.authName, tc.ok)
		}
	}

	long := ""
	for len(long) < 250 {
		long += "abcdefghi."
	}
	if _, _, ok := SplitDoTUpstream("9.9.9.9:853#" + long + "example"); ok {
		t.Error("a name over 253 bytes was accepted")
	}
	if _, _, ok := SplitDoTUpstream("9.9.9.9:853#" + string(make([]byte, 64)) + ".example"); ok {
		t.Error("a label over 63 bytes was accepted")
	}
}
