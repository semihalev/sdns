package cookie

import (
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"testing"
	"time"
)

// sipVectors are the reference implementation's SipHash-2-4 outputs
// (vectors.h, vectors_sip64): key 00 01 .. 0f, message 00 01 .. n-1 for
// n = 0..63, each output as its little-endian bytes.
var sipVectors = [64]string{
	"310e0edd47db6f72",
	"fd67dc93c539f874",
	"5a4fa9d909806c0d",
	"2d7efbd796666785",
	"b7877127e09427cf",
	"8da699cd64557618",
	"cee3fe586e46c9cb",
	"37d1018bf50002ab",
	"6224939a79f5f593",
	"b0e4a90bdf82009e",
	"f3b9dd94c5bb5d7a",
	"a7ad6b22462fb3f4",
	"fbe50e86bc8f1e75",
	"903d84c02756ea14",
	"eef27a8e90ca23f7",
	"e545be4961ca29a1",
	"db9bc2577fcc2a3f",
	"9447be2cf5e99a69",
	"9cd38d96f0b3c14b",
	"bd6179a71dc96dbb",
	"98eea21af25cd6be",
	"c7673b2eb0cbf2d0",
	"883ea3e395675393",
	"c8ce5ccd8c030ca8",
	"94af49f6c650adb8",
	"eab8858ade92e1bc",
	"f315bb5bb835d817",
	"adcf6b0763612e2f",
	"a5c91da7acaa4dde",
	"716595876650a2a6",
	"28ef495c53a387ad",
	"42c341d8fa92d832",
	"ce7cf2722f512771",
	"e37859f94623f3a7",
	"381205bb1ab0e012",
	"ae97a10fd434e015",
	"b4a31508beff4d31",
	"81396229f0907902",
	"4d0cf49ee5d4dcca",
	"5c73336a76d8bf9a",
	"d0a704536ba93e0e",
	"925958fcd6420cad",
	"a915c29bc8067318",
	"952b79f3bc0aa6d4",
	"f21df2e41d4535f9",
	"87577519048f53a9",
	"10a56cf5dfcd9adb",
	"eb75095ccd986cd0",
	"51a9cb9ecba312e6",
	"96afadfc2ce666c7",
	"72fe52975a4364ee",
	"5a1645b276d592a1",
	"b274cb8ebf87870a",
	"6f9bb4203de7b381",
	"eaecb2a30b22a87f",
	"9924a43cc1315724",
	"bd838d3aafbf8db7",
	"0b1a2a3265d51aea",
	"135079a3231ce660",
	"932b2846e4d70666",
	"e1915f5cb1eca46c",
	"f325965ca16d629f",
	"575ff28e60381be5",
	"724506eb4c328a95",
}

func TestSipHash24ReferenceVectors(t *testing.T) {
	var key, msg [64]byte
	for i := range msg {
		key[i%16], msg[i] = byte(i%16), byte(i)
	}
	k0 := binary.LittleEndian.Uint64(key[:8])
	k1 := binary.LittleEndian.Uint64(key[8:16])
	for n, want := range sipVectors {
		var got [8]byte
		binary.LittleEndian.PutUint64(got[:], sipHash24(k0, k1, msg[:n]))
		if hex.EncodeToString(got[:]) != want {
			t.Fatalf("message of %d bytes: %x, want %s", n, got, want)
		}
	}
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The worked examples of RFC 9018 Appendix A: each query's cookie
// classified, and each reply's cookie built, byte for byte.
func TestRFC9018Vectors(t *testing.T) {
	for _, tc := range []struct {
		name     string
		madeWith string // the key the query's server cookie was made with
		rolledTo string // the key the reply is made with, when rolled
		client   string
		query    string
		verdict  Verdict
		// verifyAt, when set, is a time the query's cookie must verify.
		verifyAt uint32
		now      uint32
		reply    string
	}{
		{
			name:     "A.1, learning a new server cookie",
			madeWith: "e5e973e5a6b2a43f48e7dc849e37bfcf",
			client:   "198.51.100.100",
			query:    "2464c4abcf10c957",
			verdict:  ClientOnly,
			now:      1559731985,
			reply:    "2464c4abcf10c957010000005cf79f111f8130c3eee29480",
		},
		{
			name:     "A.2, a renewed server cookie, 40 minutes later",
			madeWith: "e5e973e5a6b2a43f48e7dc849e37bfcf",
			client:   "198.51.100.100",
			query:    "2464c4abcf10c957010000005cf79f111f8130c3eee29480",
			verdict:  Valid,
			now:      1559734385,
			reply:    "2464c4abcf10c957010000005cf7a871d4a564a1442aca77",
		},
		{
			// The example's reply comes 1h52m after the cookie was
			// issued, outside the one-hour lifetime §4.3 recommends and
			// this server keeps: at reply time the cookie has expired,
			// and a fresh one is built. The MAC over the nonzero
			// Reserved bytes is checked at issue time.
			name:     "A.3, Reserved bytes set",
			madeWith: "e5e973e5a6b2a43f48e7dc849e37bfcf",
			client:   "203.0.113.203",
			query:    "fc93fc62807ddb8601abcdef5cf78f71a314227b6679ebf5",
			verdict:  Invalid,
			verifyAt: 1559727985,
			now:      1559734700,
			reply:    "fc93fc62807ddb86010000005cf7a9acf73a7810aca2381e",
		},
		{
			name:     "A.4, IPv6, made with the previous secret",
			madeWith: "dd3bdf9344b678b185a6f5cb60fca715",
			rolledTo: "445536bcd2513298075a5d379663c962",
			client:   "2001:db8:220:1:59de:d0f4:8769:82b8",
			query:    "22681ab97d52c298010000005cf7c57926556bd0934c72f8",
			verdict:  Valid,
			now:      1559741961,
			reply:    "22681ab97d52c298010000005cf7c609a6bb79d16625507a",
		},
	} {
		addr := netip.MustParseAddr(tc.client)
		st := NewSecret(tc.madeWith).Classify(unhex(t, tc.query), addr, tc.now)
		if st.Verdict != tc.verdict {
			t.Fatalf("%s: verdict %d, want %d", tc.name, st.Verdict, tc.verdict)
		}
		if tc.verifyAt != 0 {
			if v := NewSecret(tc.madeWith).Classify(unhex(t, tc.query), addr, tc.verifyAt).Verdict; v != Valid {
				t.Fatalf("%s: verdict %d at issue time, want valid", tc.name, v)
			}
		}
		replier := NewSecret(tc.madeWith)
		if tc.rolledTo != "" {
			replier = NewSecret(tc.rolledTo)
			// The previous secret verified the query; the reply is
			// the new secret's, so it is built fresh.
			st.echo = false
		}
		opt, ok := replier.Reply(&st)
		if !ok || hex.EncodeToString(opt[:]) != tc.reply {
			t.Fatalf("%s: reply %x (ok=%v), want %s", tc.name, opt, ok, tc.reply)
		}
		// What the server sent verifies when it comes back.
		if again := replier.Classify(opt[:], addr, tc.now); again.Verdict != Valid || !again.echo {
			t.Fatalf("%s: the reply's cookie does not verify fresh: verdict %d, echo %v", tc.name, again.Verdict, again.echo)
		}
	}
}

// The cookie of A.1, received back: valid from one hour in the past to five
// minutes in the future, echoed while under half an hour old, and bound to
// its client cookie, address and secret.
func TestClassify(t *testing.T) {
	secret := NewSecret("e5e973e5a6b2a43f48e7dc849e37bfcf")
	addr := netip.MustParseAddr("198.51.100.100")
	const issued = 1559731985
	good := unhex(t, "2464c4abcf10c957010000005cf79f111f8130c3eee29480")
	flip := func(i int) []byte {
		b := append([]byte(nil), good...)
		b[i] ^= 1
		return b
	}
	for _, tc := range []struct {
		name    string
		opt     []byte
		addr    netip.Addr
		secret  Secret
		now     uint32
		verdict Verdict
		echo    bool
	}{
		{"just issued", good, addr, secret, issued, Valid, true},
		{"29m59s old", good, addr, secret, issued + 1799, Valid, true},
		{"half an hour old", good, addr, secret, issued + 1800, Valid, false},
		{"one hour old", good, addr, secret, issued + 3600, Valid, false},
		{"one hour and a second old", good, addr, secret, issued + 3601, Invalid, false},
		{"five minutes ahead", good, addr, secret, issued - 300, Valid, true},
		{"five minutes and a second ahead", good, addr, secret, issued - 301, Invalid, false},
		{"another client cookie", flip(0), addr, secret, issued, Invalid, false},
		{"another version", flip(8), addr, secret, issued, Invalid, false},
		{"another timestamp", flip(15), addr, secret, issued, Invalid, false},
		{"another hash", flip(23), addr, secret, issued, Invalid, false},
		{"another address", good, netip.MustParseAddr("198.51.100.101"), secret, issued, Invalid, false},
		{"the address as IPv4-mapped IPv6", good, netip.MustParseAddr("::ffff:198.51.100.100"), secret, issued, Valid, true},
		{"another secret", good, addr, NewSecret("dd3bdf9344b678b185a6f5cb60fca715"), issued, Invalid, false},
		{"no address", good, netip.Addr{}, secret, issued, Invalid, false},
		{"a 16..40 byte cookie of another shape", append(good[:24:24], 0), addr, secret, issued, Invalid, false},
		{"no cookie", nil, addr, secret, issued, None, false},
		{"client cookie only", good[:8], addr, secret, issued, ClientOnly, false},
		{"5 bytes", good[:5], addr, secret, issued, Malformed, false},
		{"12 bytes", good[:12], addr, secret, issued, Malformed, false},
		{"41 bytes", make([]byte, 41), addr, secret, issued, Malformed, false},
	} {
		st := tc.secret.Classify(tc.opt, tc.addr, tc.now)
		if st.Verdict != tc.verdict || st.echo != tc.echo {
			t.Fatalf("%s: verdict %d echo %v, want %d echo %v", tc.name, st.Verdict, st.echo, tc.verdict, tc.echo)
		}
	}
}

// RFC 1982 serial arithmetic: a cookie made just before the 32-bit
// timestamp wraps still verifies just after it.
func TestClassifyAcrossTheTimestampWrap(t *testing.T) {
	secret := NewSecret("e5e973e5a6b2a43f48e7dc849e37bfcf")
	addr := netip.MustParseAddr("2001:db8::53")
	issued := uint32(0xffffff00)
	st := secret.Classify(unhex(t, "2464c4abcf10c957"), addr, issued)
	opt, ok := secret.Reply(&st)
	if !ok {
		t.Fatal("no reply cookie")
	}
	if got := secret.Classify(opt[:], addr, issued+512); got.Verdict != Valid || !got.echo {
		t.Fatalf("512s after issue, across the wrap: verdict %d echo %v, want valid and echoed", got.Verdict, got.echo)
	}
	if got := secret.Classify(opt[:], addr, issued+maxAge+1); got.Verdict != Invalid {
		t.Fatalf("an hour and a second after issue, across the wrap: verdict %d, want invalid", got.Verdict)
	}
}

// No reply cookie without a client cookie to answer, or an address to bind
// a new one to.
func TestReplyNeedsAClientCookieAndAnAddress(t *testing.T) {
	secret := NewSecret("secret")
	now := uint32(time.Now().Unix()) //nolint:gosec // a cookie timestamp is the epoch second modulo 2^32 (RFC 9018 §4.3)
	addr := netip.MustParseAddr("192.0.2.1")
	for _, st := range []State{
		secret.Classify(nil, addr, now),
		secret.Classify(make([]byte, 5), addr, now),
		secret.Classify(make([]byte, 8), netip.Addr{}, now),
	} {
		if _, ok := secret.Reply(&st); ok {
			t.Fatalf("verdict %d: a reply cookie was built", st.Verdict)
		}
	}
}

// A secret that is not 32 hex digits is hashed down to a key, and the key
// is the secret's alone.
func TestNewSecret(t *testing.T) {
	if NewSecret("e5e973e5a6b2a43f48e7dc849e37bfcf") != (Secret{k0: 0x3fa4b2a6e573e9e5, k1: 0xcfbf379e84dce748}) {
		t.Fatal("32 hex digits are not the key itself")
	}
	one, again, two := NewSecret("one"), NewSecret("one"), NewSecret("two")
	if one == two || one != again {
		t.Fatal("derived keys do not follow the secret")
	}
}

func BenchmarkClassifyValid(b *testing.B) {
	secret := NewSecret("e5e973e5a6b2a43f48e7dc849e37bfcf")
	addr := netip.MustParseAddr("198.51.100.100")
	opt, _ := hex.DecodeString("2464c4abcf10c957010000005cf79f111f8130c3eee29480")
	b.ReportAllocs()
	for b.Loop() {
		if secret.Classify(opt, addr, 1559731985).Verdict != Valid {
			b.Fatal("invalid")
		}
	}
}
