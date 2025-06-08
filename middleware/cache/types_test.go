package cache

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
				assert.Equal(t, dns.RcodeServerFailure, restored.Rcode)

				opt := restored.IsEdns0()
				require.NotNil(t, opt)
				require.Len(t, opt.Option, 1)

				ede, ok := opt.Option[0].(*dns.EDNS0_EDE)
				require.True(t, ok)
				assert.Equal(t, uint16(dns.ExtendedErrorCodeNetworkError), ede.InfoCode)
				assert.Equal(t, "Network unreachable", ede.ExtraText)
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
				assert.Equal(t, dns.RcodeNameError, restored.Rcode)

				opt := restored.IsEdns0()
				require.NotNil(t, opt)
				require.Len(t, opt.Option, 1)

				ede, ok := opt.Option[0].(*dns.EDNS0_EDE)
				require.True(t, ok)
				assert.Equal(t, uint16(dns.ExtendedErrorCodeStaleNXDOMAINAnswer), ede.InfoCode)
				assert.Equal(t, "Stale NXDOMAIN response", ede.ExtraText)
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
				assert.Equal(t, dns.RcodeSuccess, restored.Rcode)
				assert.Len(t, restored.Answer, 1)

				opt := restored.IsEdns0()
				require.NotNil(t, opt)
				require.Len(t, opt.Option, 1)

				ede, ok := opt.Option[0].(*dns.EDNS0_EDE)
				require.True(t, ok)
				assert.Equal(t, uint16(dns.ExtendedErrorCodeStaleAnswer), ede.InfoCode)
				assert.Equal(t, "Stale data served", ede.ExtraText)
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
				assert.Equal(t, dns.RcodeServerFailure, restored.Rcode)

				opt := restored.IsEdns0()
				require.NotNil(t, opt)
				// Should only preserve the first EDE
				require.Len(t, opt.Option, 1)

				ede, ok := opt.Option[0].(*dns.EDNS0_EDE)
				require.True(t, ok)
				assert.Equal(t, uint16(dns.ExtendedErrorCodeDNSSECIndeterminate), ede.InfoCode)
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
				assert.Equal(t, dns.RcodeServerFailure, restored.Rcode)
				// No EDE should be added if request doesn't have EDNS
				assert.Nil(t, restored.IsEdns0())
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
				assert.Equal(t, dns.RcodeServerFailure, restored.Rcode)

				opt := restored.IsEdns0()
				require.NotNil(t, opt)
				require.Len(t, opt.Option, 1)

				ede, ok := opt.Option[0].(*dns.EDNS0_EDE)
				require.True(t, ok)
				assert.Equal(t, uint16(dns.ExtendedErrorCodeOther), ede.InfoCode)
				assert.Equal(t, "", ede.ExtraText)
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
				assert.Equal(t, dns.RcodeServerFailure, restored.Rcode)

				opt := restored.IsEdns0()
				require.NotNil(t, opt)
				// Should only have EDE, not the cookie
				require.Len(t, opt.Option, 1)

				ede, ok := opt.Option[0].(*dns.EDNS0_EDE)
				require.True(t, ok)
				assert.Equal(t, uint16(dns.ExtendedErrorCodeNetworkError), ede.InfoCode)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create cache entry
			entry := NewCacheEntry(tt.msg, 300*time.Second, 0)
			require.NotNil(t, entry)

			// Convert back to message
			restored := entry.ToMsg(tt.req)
			require.NotNil(t, restored)

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
	require.NotNil(t, entry)
	assert.Nil(t, entry.ede)

	// Restore with EDNS request
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	req.SetEdns0(512, true)

	restored := entry.ToMsg(req)
	require.NotNil(t, restored)
	assert.Len(t, restored.Answer, 1)
	assert.Nil(t, restored.IsEdns0()) // No OPT should be added
}
