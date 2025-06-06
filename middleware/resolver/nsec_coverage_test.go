package resolver

import (
	"testing"
)

func TestNSECCoversEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		owner    string
		next     string
		qname    string
		expected bool
	}{
		{
			name:     "Normal coverage",
			owner:    "a.example.",
			next:     "c.example.",
			qname:    "b.example.",
			expected: true,
		},
		{
			name:     "Not covered - before range",
			owner:    "b.example.",
			next:     "d.example.",
			qname:    "a.example.",
			expected: false,
		},
		{
			name:     "Not covered - after range",
			owner:    "a.example.",
			next:     "c.example.",
			qname:    "d.example.",
			expected: false,
		},
		{
			name:     "Wrap-around case - covered before next",
			owner:    "z.example.",
			next:     "b.example.",
			qname:    "a.example.",
			expected: true,
		},
		{
			name:     "Wrap-around case - covered after owner",
			owner:    "y.example.",
			next:     "a.example.",
			qname:    "z.example.",
			expected: true,
		},
		{
			name:     "Single name zone - covers other names",
			owner:    "net.com.",
			next:     "net.com.",
			qname:    "iowatelecom.net.com.",
			expected: true,
		},
		{
			name:     "Single name zone - doesn't cover itself",
			owner:    "net.com.",
			next:     "net.com.",
			qname:    "net.com.",
			expected: false,
		},
		{
			name:     "Root zone edge case",
			owner:    "com.",
			next:     "commbank.",
			qname:    "comm.",
			expected: true,
		},
		{
			name:     "Exact match on owner",
			owner:    "example.com.",
			next:     "foo.com.",
			qname:    "example.com.",
			expected: false,
		},
		{
			name:     "Exact match on next",
			owner:    "example.com.",
			next:     "foo.com.",
			qname:    "foo.com.",
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := nsecCovers(tc.owner, tc.next, tc.qname)
			if result != tc.expected {
				t.Errorf("nsecCovers(%q, %q, %q) = %v, want %v",
					tc.owner, tc.next, tc.qname, result, tc.expected)
			}
		})
	}
}
