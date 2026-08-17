package cache

import (
	"reflect"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestEDEPreservation(t *testing.T) {
	tests := []struct {
		name     string
		msg      *dns.Msg
		req      *dns.Msg
		expected func(*testing.T, *dns.Msg, *dns.Msg)
	}{
		{
			name: "EDE with SERVFAIL",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetReply(new(dns.Msg))
				m.Rcode = dns.RcodeServerFailure

				opt := &dns.OPT{
					Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT},
				}
				ede := &dns.EDNS0_EDE{
					InfoCode:  dns.ExtendedErrorCodeNetworkError,
					ExtraText: "Network unreachable",
				}
				opt.Option = append(opt.Option, ede)
				m.Extra = append(m.Extra, opt)

				return m
			}(),
			req: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				m.SetEdns0(512, true)
				return m
			}(),
			expected: func(t *testing.T, original, restored *dns.Msg) {
				if !reflect.DeepEqual(dns.RcodeServerFailure, restored.Rcode) {
					t.Errorf("restored.Rcode = %v, want %v", restored.Rcode, dns.RcodeServerFailure)
				}

				opt := restored.IsEdns0()
				if opt == nil {
					t.Fatalf("opt is nil")
				}
				if len(opt.Option) != 1 {
					t.Fatalf("len(opt.Option) = %d, want %d", len(opt.Option), 1)
				}

				ede, ok := opt.Option[0].(*dns.EDNS0_EDE)
				if !(ok) {
					t.Fatalf("ok is false")
				}
				if !reflect.DeepEqual(dns.ExtendedErrorCodeNetworkError, ede.InfoCode) {
					t.Errorf("ede.InfoCode = %v, want %v", ede.InfoCode, dns.ExtendedErrorCodeNetworkError)
				}
				if !reflect.DeepEqual("Network unreachable", ede.ExtraText) {
					t.Errorf("ede.ExtraText = %v, want %v", ede.ExtraText, "Network unreachable")
				}
			},
		},
		{
			name: "EDE with NXDOMAIN",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetReply(new(dns.Msg))
				m.Rcode = dns.RcodeNameError

				opt := &dns.OPT{
					Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT},
				}
				ede := &dns.EDNS0_EDE{
					InfoCode:  dns.ExtendedErrorCodeStaleNXDOMAINAnswer,
					ExtraText: "Stale NXDOMAIN response",
				}
				opt.Option = append(opt.Option, ede)
				m.Extra = append(m.Extra, opt)

				return m
			}(),
			req: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("nonexistent.com.", dns.TypeA)
				m.SetEdns0(512, true)
				return m
			}(),
			expected: func(t *testing.T, original, restored *dns.Msg) {
				if !reflect.DeepEqual(dns.RcodeNameError, restored.Rcode) {
					t.Errorf("restored.Rcode = %v, want %v", restored.Rcode, dns.RcodeNameError)
				}

				opt := restored.IsEdns0()
				if opt == nil {
					t.Fatalf("opt is nil")
				}
				if len(opt.Option) != 1 {
					t.Fatalf("len(opt.Option) = %d, want %d", len(opt.Option), 1)
				}

				ede, ok := opt.Option[0].(*dns.EDNS0_EDE)
				if !(ok) {
					t.Fatalf("ok is false")
				}
				if !reflect.DeepEqual(dns.ExtendedErrorCodeStaleNXDOMAINAnswer, ede.InfoCode) {
					t.Errorf("ede.InfoCode = %v, want %v", ede.InfoCode, dns.ExtendedErrorCodeStaleNXDOMAINAnswer)
				}
				if !reflect.DeepEqual("Stale NXDOMAIN response", ede.ExtraText) {
					t.Errorf("ede.ExtraText = %v, want %v", ede.ExtraText, "Stale NXDOMAIN response")
				}
			},
		},
		{
			name: "EDE with NOERROR",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetReply(new(dns.Msg))
				m.Rcode = dns.RcodeSuccess

				opt := &dns.OPT{
					Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT},
				}
				ede := &dns.EDNS0_EDE{
					InfoCode:  dns.ExtendedErrorCodeStaleAnswer,
					ExtraText: "Stale data served",
				}
				opt.Option = append(opt.Option, ede)
				m.Extra = append(m.Extra, opt)

				// Add an answer
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{
						Name:   "example.com.",
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					A: []byte{1, 2, 3, 4},
				})

				return m
			}(),
			req: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				m.SetEdns0(512, true)
				return m
			}(),
			expected: func(t *testing.T, original, restored *dns.Msg) {
				if !reflect.DeepEqual(dns.RcodeSuccess, restored.Rcode) {
					t.Errorf("restored.Rcode = %v, want %v", restored.Rcode, dns.RcodeSuccess)
				}
				if len(restored.Answer) != 1 {
					t.Errorf("len(restored.Answer) = %d, want %d", len(restored.Answer), 1)
				}

				opt := restored.IsEdns0()
				if opt == nil {
					t.Fatalf("opt is nil")
				}
				if len(opt.Option) != 1 {
					t.Fatalf("len(opt.Option) = %d, want %d", len(opt.Option), 1)
				}

				ede, ok := opt.Option[0].(*dns.EDNS0_EDE)
				if !(ok) {
					t.Fatalf("ok is false")
				}
				if !reflect.DeepEqual(dns.ExtendedErrorCodeStaleAnswer, ede.InfoCode) {
					t.Errorf("ede.InfoCode = %v, want %v", ede.InfoCode, dns.ExtendedErrorCodeStaleAnswer)
				}
				if !reflect.DeepEqual("Stale data served", ede.ExtraText) {
					t.Errorf("ede.ExtraText = %v, want %v", ede.ExtraText, "Stale data served")
				}
			},
		},
		{
			name: "Multiple EDE options",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetReply(new(dns.Msg))
				m.Rcode = dns.RcodeServerFailure

				opt := &dns.OPT{
					Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT},
				}

				// Add multiple EDE options
				ede1 := &dns.EDNS0_EDE{
					InfoCode:  dns.ExtendedErrorCodeDNSSECIndeterminate,
					ExtraText: "DNSSEC validation in progress",
				}
				ede2 := &dns.EDNS0_EDE{
					InfoCode:  dns.ExtendedErrorCodeCachedError,
					ExtraText: "Cached error response",
				}
				opt.Option = append(opt.Option, ede1, ede2)
				m.Extra = append(m.Extra, opt)

				return m
			}(),
			req: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				m.SetEdns0(512, true)
				return m
			}(),
			expected: func(t *testing.T, original, restored *dns.Msg) {
				if !reflect.DeepEqual(dns.RcodeServerFailure, restored.Rcode) {
					t.Errorf("restored.Rcode = %v, want %v", restored.Rcode, dns.RcodeServerFailure)
				}

				opt := restored.IsEdns0()
				if opt == nil {
					t.Fatalf("opt is nil")
				}
				// Should only preserve the first EDE
				if len(opt.Option) != 1 {
					t.Fatalf("len(opt.Option) = %d, want %d", len(opt.Option), 1)
				}

				ede, ok := opt.Option[0].(*dns.EDNS0_EDE)
				if !(ok) {
					t.Fatalf("ok is false")
				}
				if !reflect.DeepEqual(dns.ExtendedErrorCodeDNSSECIndeterminate, ede.InfoCode) {
					t.Errorf("ede.InfoCode = %v, want %v", ede.InfoCode, dns.ExtendedErrorCodeDNSSECIndeterminate)
				}
			},
		},
		{
			name: "No EDNS in request",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetReply(new(dns.Msg))
				m.Rcode = dns.RcodeServerFailure

				opt := &dns.OPT{
					Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT},
				}
				ede := &dns.EDNS0_EDE{
					InfoCode:  dns.ExtendedErrorCodeNetworkError,
					ExtraText: "Network error",
				}
				opt.Option = append(opt.Option, ede)
				m.Extra = append(m.Extra, opt)

				return m
			}(),
			req: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				// No EDNS0
				return m
			}(),
			expected: func(t *testing.T, original, restored *dns.Msg) {
				if !reflect.DeepEqual(dns.RcodeServerFailure, restored.Rcode) {
					t.Errorf("restored.Rcode = %v, want %v", restored.Rcode, dns.RcodeServerFailure)
				}
				// No EDE should be added if request doesn't have EDNS
				if restored.IsEdns0() != nil {
					t.Errorf("restored.IsEdns0() = %v, want nil", restored.IsEdns0())
				}
			},
		},
		{
			name: "Empty EDE text",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetReply(new(dns.Msg))
				m.Rcode = dns.RcodeServerFailure

				opt := &dns.OPT{
					Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT},
				}
				ede := &dns.EDNS0_EDE{
					InfoCode:  dns.ExtendedErrorCodeOther,
					ExtraText: "", // Empty text
				}
				opt.Option = append(opt.Option, ede)
				m.Extra = append(m.Extra, opt)

				return m
			}(),
			req: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				m.SetEdns0(512, true)
				return m
			}(),
			expected: func(t *testing.T, original, restored *dns.Msg) {
				if !reflect.DeepEqual(dns.RcodeServerFailure, restored.Rcode) {
					t.Errorf("restored.Rcode = %v, want %v", restored.Rcode, dns.RcodeServerFailure)
				}

				opt := restored.IsEdns0()
				if opt == nil {
					t.Fatalf("opt is nil")
				}
				if len(opt.Option) != 1 {
					t.Fatalf("len(opt.Option) = %d, want %d", len(opt.Option), 1)
				}

				ede, ok := opt.Option[0].(*dns.EDNS0_EDE)
				if !(ok) {
					t.Fatalf("ok is false")
				}
				if !reflect.DeepEqual(dns.ExtendedErrorCodeOther, ede.InfoCode) {
					t.Errorf("ede.InfoCode = %v, want %v", ede.InfoCode, dns.ExtendedErrorCodeOther)
				}
				if !reflect.DeepEqual("", ede.ExtraText) {
					t.Errorf("ede.ExtraText = %v, want %v", ede.ExtraText, "")
				}
			},
		},
		{
			name: "OPT with non-EDE options",
			msg: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetReply(new(dns.Msg))
				m.Rcode = dns.RcodeServerFailure

				opt := &dns.OPT{
					Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT},
				}

				// Add non-EDE option
				cookie := &dns.EDNS0_COOKIE{
					Code:   dns.EDNS0COOKIE,
					Cookie: "test",
				}
				opt.Option = append(opt.Option, cookie)

				// Add EDE
				ede := &dns.EDNS0_EDE{
					InfoCode:  dns.ExtendedErrorCodeNetworkError,
					ExtraText: "Network error",
				}
				opt.Option = append(opt.Option, ede)

				m.Extra = append(m.Extra, opt)

				return m
			}(),
			req: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("example.com.", dns.TypeA)
				m.SetEdns0(512, true)
				return m
			}(),
			expected: func(t *testing.T, original, restored *dns.Msg) {
				if !reflect.DeepEqual(dns.RcodeServerFailure, restored.Rcode) {
					t.Errorf("restored.Rcode = %v, want %v", restored.Rcode, dns.RcodeServerFailure)
				}

				opt := restored.IsEdns0()
				if opt == nil {
					t.Fatalf("opt is nil")
				}
				// Should only have EDE, not the cookie
				if len(opt.Option) != 1 {
					t.Fatalf("len(opt.Option) = %d, want %d", len(opt.Option), 1)
				}

				ede, ok := opt.Option[0].(*dns.EDNS0_EDE)
				if !(ok) {
					t.Fatalf("ok is false")
				}
				if !reflect.DeepEqual(dns.ExtendedErrorCodeNetworkError, ede.InfoCode) {
					t.Errorf("ede.InfoCode = %v, want %v", ede.InfoCode, dns.ExtendedErrorCodeNetworkError)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create cache entry
			entry := NewCacheEntry(tt.msg, 300*time.Second, 0)
			if entry == nil {
				t.Fatalf("entry is nil")
			}

			// Convert back to message
			restored := entry.ToMsg(tt.req)
			if restored == nil {
				t.Fatalf("restored is nil")
			}

			// Verify expectations
			tt.expected(t, tt.msg, restored)
		})
	}
}

func TestCacheEntryWithoutEDE(t *testing.T) {
	// Message without any OPT record
	msg := new(dns.Msg)
	msg.SetReply(new(dns.Msg))
	msg.Answer = append(msg.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: []byte{1, 2, 3, 4},
	})

	entry := NewCacheEntry(msg, 300*time.Second, 0)
	if entry == nil {
		t.Fatalf("entry is nil")
	}
	if entry.ede != nil {
		t.Errorf("entry.ede = %v, want nil", entry.ede)
	}

	// Restore with EDNS request
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	req.SetEdns0(512, true)

	restored := entry.ToMsg(req)
	if restored == nil {
		t.Fatalf("restored is nil")
	}
	if len(restored.Answer) != 1 {
		t.Errorf("len(restored.Answer) = %d, want %d", len(restored.Answer), 1)
	}
	if restored.IsEdns0() != nil {
		t.Errorf("restored.IsEdns0() = %v, want nil", restored.IsEdns0())
	} // No OPT should be added
}
