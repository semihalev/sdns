package dnsname

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestAppendWireNamePresentation(t *testing.T) {
	for _, tc := range []struct {
		name string
		want []byte
	}{
		{".", []byte{0}},
		{"Example.COM", []byte{7, 'E', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'C', 'O', 'M', 0}},
		{"Example.COM.", []byte{7, 'E', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'C', 'O', 'M', 0}},
		{`a\.b`, []byte{3, 'a', '.', 'b', 0}},
		{`a\\b.`, []byte{3, 'a', '\\', 'b', 0}},
		{`\000.\255.\999`, []byte{1, 0, 1, 255, 1, 231, 0}},
		{`\1.\12.\12x.\1234`, []byte{1, '1', 2, '1', '2', 3, '1', '2', 'x', 2, 123, '4', 0}},
		{"ü", []byte{2, 0xc3, 0xbc, 0}},
		{"\\ü", []byte{2, 0xc3, 0xbc, 0}},
		{`\195\188.`, []byte{2, 0xc3, 0xbc, 0}},
		{"ü\\.x", []byte{4, 0xc3, 0xbc, '.', 'x', 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := AppendWireName(nil, tc.name)
			if !ok || !bytes.Equal(got, tc.want) {
				t.Fatalf("AppendWireName(%q) = %v, %v; want %v, true", tc.name, got, ok, tc.want)
			}
		})
	}
}

func TestAppendWireNameUnicodeFinalDot(t *testing.T) {
	// Construct the expected wire bytes directly: UTF-8 before escaped dots
	// must not change whether the final dot is label content or the root.
	labelLengths := [...]byte{3, 3, 4, 4}
	for slashes := 1; slashes <= 4; slashes++ {
		for _, child := range []bool{false, true} {
			name := "ü" + strings.Repeat("\\", slashes) + "."
			label := []byte{0xc3, 0xbc}
			for i := 0; i < slashes/2; i++ {
				label = append(label, '\\')
			}
			if slashes%2 == 1 {
				label = append(label, '.')
			}
			want := []byte{labelLengths[slashes-1]}
			want = append(want, label...)
			want = append(want, 0)
			if child {
				name = "child." + name
				want = append([]byte{5, 'c', 'h', 'i', 'l', 'd'}, want...)
			}
			t.Run(fmt.Sprintf("slashes%d/child%v", slashes, child), func(t *testing.T) {
				got, ok := AppendWireName(nil, name)
				if !ok || !bytes.Equal(got, want) {
					t.Fatalf("AppendWireName(%q) = %v, %v; want %v, true", name, got, ok, want)
				}
			})
		}
	}
}

func TestAppendWireNamePresentationLimits(t *testing.T) {
	label63 := strings.Repeat("a", 63)
	label61 := strings.Repeat("b", 61)
	name255 := strings.Join([]string{label63, label63, label63, label61}, ".")
	for _, tc := range []struct {
		name    string
		ok      bool
		wireLen int
	}{
		{label63, true, 65},
		{strings.Repeat("a", 64), false, 0},
		{strings.Repeat(`\097`, 63), true, 65},
		{strings.Repeat(`\097`, 64), false, 0},
		{name255, true, 255},
		{name255 + ".", true, 255},
		{name255 + "b", false, 0},
		{name255 + "b.", false, 0},
		{"", false, 0},
		{".a", false, 0},
		{"a..b", false, 0},
		{"a..", false, 0},
		{"..", false, 0},
		{"\\", false, 0},
		{"a.\\", false, 0},
		{"a\\", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := AppendWireName(nil, tc.name)
			if ok != tc.ok || len(got) != tc.wireLen {
				t.Fatalf("AppendWireName(%q) = %v, %v; want length %d, ok %v", tc.name, got, ok, tc.wireLen, tc.ok)
			}
		})
	}
}

func TestAppendWireNameDestinationPrefix(t *testing.T) {
	prefix := []byte{0xde, 0xad, 0xbe, 0xef}
	for _, capacity := range []int{len(prefix), 512} {
		for _, name := range []string{"a.b.", ".", "a..b", strings.Repeat("a", 64), strings.Repeat("a", 63) + ".b\\"} {
			t.Run(fmt.Sprintf("cap%d/%s", capacity, name), func(t *testing.T) {
				dst := make([]byte, len(prefix), capacity)
				copy(dst, prefix)
				got, ok := AppendWireName(dst, name)
				want := prefix
				switch name {
				case "a.b.":
					want = append(append([]byte(nil), prefix...), 1, 'a', 1, 'b', 0)
				case ".":
					want = append(append([]byte(nil), prefix...), 0)
				}
				if ok != (name == "a.b." || name == ".") || !bytes.Equal(got, want) || !bytes.Equal(dst, prefix) {
					t.Fatalf("AppendWireName(%q): got %v, %v; want %v; original prefix %v", name, got, ok, want, dst)
				}
			})
		}
	}
	// Wire size counts only the appended name, even with a long prefix.
	dst := bytes.Repeat([]byte{0xaa}, 256)
	name := strings.Join([]string{strings.Repeat("a", 63), strings.Repeat("b", 63), strings.Repeat("c", 63), strings.Repeat("d", 61)}, ".")
	got, ok := AppendWireName(dst, name)
	if !ok || len(got) != len(dst)+255 || !bytes.Equal(got[:len(dst)], dst) {
		t.Fatalf("255-octet name with prefix: length %d, ok %v", len(got), ok)
	}
	got, ok = AppendWireName(dst, name+"d")
	if ok || !bytes.Equal(got, dst) {
		t.Fatalf("256-octet name with prefix: got %v, ok %v", got, ok)
	}
}

func TestAppendWireNamePresentationRoundTripEveryByte(t *testing.T) {
	for oct := 0; oct < 256; oct++ {
		want := []byte{1, byte(oct), 0}
		presentation, ok := AppendPresentation(nil, want)
		if !ok {
			t.Fatalf("AppendPresentation refused byte %d", oct)
		}
		got, ok := AppendWireName(nil, string(presentation))
		if !ok || !bytes.Equal(got, want) {
			t.Fatalf("byte %d, presentation %q: got %v, %v; want %v", oct, presentation, got, ok, want)
		}
	}
}
