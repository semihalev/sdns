package edns

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/dnsutil"
	"github.com/semihalev/sdns/internal/wire"
	"github.com/semihalev/sdns/middleware"
)

// TestWireOPTLenMatchesPackedOPT pins the arithmetic reservation against the
// record it predicts. Under-reserving would force a second body allocation
// and copy in WriteWire; over-reserving would waste bytes on every hit.
func TestWireOPTLenMatchesPackedOPT(t *testing.T) {
	cases := []struct {
		name    string
		cookie  string
		nsidStr string
		nsid    bool
	}{
		{name: "bare"},
		{name: "cookie", cookie: "0123456789abcdef"},
		{name: "nsid", nsidStr: "sdns-node-1", nsid: true},
		{name: "cookie+nsid", cookie: "0123456789abcdef", nsidStr: "sdns-node-1", nsid: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := &ResponseWriter{
				ResponseWriter: &wireCountingWriter{},
				EDNS:           &EDNS{cookiesecret: "abcdef0123456789", nsidstr: tc.nsidStr},
				opt:            new(dns.OPT),
				do:             true,
				cookie:         tc.cookie,
				nsid:           tc.nsid,
			}
			w.opt.Hdr.Name = "."
			w.opt.Hdr.Rrtype = dns.TypeOPT
			w.opt.SetUDPSize(dnsutil.DefaultMsgSize)
			w.respUDPSize = dnsutil.DefaultMsgSize

			predicted, ok := w.wireOPTLen()
			if !ok {
				t.Fatal("reservation refused for an ordinary client")
			}
			encoded, ok := w.appendWireOPT(nil, middleware.WireInfo{})
			if !ok {
				t.Fatal("OPT encoding refused")
			}
			if got := len(encoded); got != predicted {
				t.Fatalf("reserved %d bytes, packed OPT is %d", predicted, got)
			}
		})
	}
}

// TestWireReadyAllocatesNothing is the property the whole preflight exists
// for: a request the caller may still refuse must not have paid for a
// composed OPT, a generated cookie, or a packing buffer.
func TestWireReadyAllocatesNothing(t *testing.T) {
	base := &wireCountingWriter{}
	w := &ResponseWriter{
		ResponseWriter: base,
		EDNS:           &EDNS{cookiesecret: "abcdef0123456789", nsidstr: "sdns-node-1"},
		opt:            new(dns.OPT),
		size:           dnsutil.DefaultMsgSize,
		do:             true,
		cookie:         "0123456789abcdef",
		nsid:           true,
	}
	w.opt.Hdr.Name = "."
	w.opt.Hdr.Rrtype = dns.TypeOPT
	w.opt.SetUDPSize(dnsutil.DefaultMsgSize)
	w.respUDPSize = dnsutil.DefaultMsgSize

	if allocs := testing.AllocsPerRun(200, func() {
		if _, ok := w.WireReady(); !ok {
			t.Fatal("preflight refused")
		}
	}); allocs != 0 {
		t.Fatalf("WireReady allocated %.0f objects per call; the preflight must be free "+
			"so a refused request pays nothing", allocs)
	}
}

// wireCountingWriter is a byte sink that reports itself wire-capable so the
// preflight can walk a complete chain without a transport.
type wireCountingWriter struct {
	middleware.ResponseWriter
	writes int
}

func (w *wireCountingWriter) WireReady() (middleware.WireCapability, bool) {
	return middleware.WireCapability{}, true
}

func (w *wireCountingWriter) WriteWire(body []byte, _ middleware.WireInfo) error {
	w.writes++
	return nil
}

func (w *wireCountingWriter) Proto() string { return "udp" }

// remoteIP is built once: net.IPv4 allocates on every call, and a helper
// that allocates would be indistinguishable from the code under test in an
// allocation assertion. The real writer likewise returns a stored value.
var remoteIP = net.IPv4(198, 51, 100, 7)

func (w *wireCountingWriter) RemoteIP() net.IP { return remoteIP }

// TestAppendWireOPTMatchesLibraryPacking is the encoder's contract: the
// bytes it writes must be byte-for-byte what the library produces from the
// equivalent record. Owning the encoding is only safe while it stays
// indistinguishable on the wire.
func TestAppendWireOPTMatchesLibraryPacking(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cookie  string
		nsidStr string
		nsid    bool
		do      bool
		udpSize uint16
		edeCode uint16
		edeText string
		hasEDE  bool
	}{
		{name: "bare", do: true, udpSize: 1232},
		{name: "no_do", udpSize: 512},
		{name: "cookie", cookie: "0123456789abcdef", do: true, udpSize: 1232},
		{name: "nsid", nsidStr: "sdns-node-1", nsid: true, do: true, udpSize: 4096},
		{name: "cookie+nsid", cookie: "AABBCCDD00112233", nsidStr: "n", nsid: true, do: true, udpSize: 1232},
		{name: "ede", do: true, udpSize: 1232, hasEDE: true,
			edeCode: dns.ExtendedErrorCodeDNSBogus, edeText: "signature expired"},
		{name: "cookie+ede", cookie: "0123456789abcdef", do: true, udpSize: 1232, hasEDE: true,
			edeCode: dns.ExtendedErrorCodeStaleAnswer, edeText: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := &ResponseWriter{
				ResponseWriter: &wireCountingWriter{},
				EDNS:           &EDNS{cookiesecret: "abcdef0123456789", nsidstr: tc.nsidStr},
				opt:            new(dns.OPT),
				do:             tc.do,
				cookie:         tc.cookie,
				nsid:           tc.nsid,
			}
			w.opt.Hdr.Name = "."
			w.opt.Hdr.Rrtype = dns.TypeOPT
			w.opt.SetUDPSize(tc.udpSize)
			w.respUDPSize = tc.udpSize

			info := middleware.WireInfo{
				HasEDE:  tc.hasEDE,
				EDECode: tc.edeCode,
				EDEText: tc.edeText,
			}
			ours, ok := w.appendWireOPT(nil, info)
			if !ok {
				t.Fatal("encoding refused")
			}

			// The library's equivalent: the same record, built the way the
			// message path builds it, packed by miekg.
			reference := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
			reference.SetUDPSize(tc.udpSize)
			reference.SetDo(tc.do)
			if option, has := w.cookieOption(); has {
				reference.Option = append(reference.Option, option)
			}
			if option, has := w.nsidOption(); has {
				reference.Option = append(reference.Option, option)
			}
			if tc.hasEDE {
				reference.Option = append(reference.Option, &dns.EDNS0_EDE{
					InfoCode:  tc.edeCode,
					ExtraText: tc.edeText,
				})
			}
			buf := make([]byte, dns.Len(reference)+16)
			n, err := dns.PackRR(reference, buf, 0, nil, false)
			if err != nil {
				t.Fatalf("reference pack: %v", err)
			}
			want := buf[:n]

			if len(ours) != len(want) {
				t.Fatalf("encoded %d bytes, library packs %d\n ours: %x\n want: %x",
					len(ours), len(want), ours, want)
			}
			for i := range want {
				if ours[i] != want[i] {
					t.Fatalf("byte %d diverges: %x vs %x\n ours: %x\n want: %x",
						i, ours[i], want[i], ours, want)
				}
			}
		})
	}
}

// TestServeWireOPTAllocatesNothing pins the encoder's cost: composing the
// reply's OPT, cookie digest included, must not touch the allocator.
func TestServeWireOPTAllocatesNothing(t *testing.T) {
	w := &ResponseWriter{
		ResponseWriter: &wireCountingWriter{},
		EDNS:           &EDNS{cookiesecret: "abcdef0123456789", nsidstr: "sdns-node-1"},
		opt:            new(dns.OPT),
		do:             true,
		cookie:         "0123456789abcdef",
		nsid:           true,
	}
	w.opt.Hdr.Name = "."
	w.opt.Hdr.Rrtype = dns.TypeOPT
	w.opt.SetUDPSize(dnsutil.DefaultMsgSize)
	w.respUDPSize = dnsutil.DefaultMsgSize

	reserve, _ := w.wireOPTLen()
	const edeText = "stale answer served from cache"
	info := middleware.WireInfo{
		HasEDE:  true,
		EDECode: dns.ExtendedErrorCodeStaleAnswer,
		EDEText: edeText,
	}
	body := make([]byte, 0, reserve+wire.OPTOptionHdrLen+2+len(edeText))
	if allocs := testing.AllocsPerRun(200, func() {
		if _, ok := w.appendWireOPT(body, info); !ok {
			t.Fatal("encoding refused")
		}
	}); allocs != 0 {
		t.Fatalf("appendWireOPT allocated %.0f objects per call", allocs)
	}
}
