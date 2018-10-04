package main

import (
	"strings"
	"testing"
)

func Test_keyGen(t *testing.T) {

	q := Question{"@", "A", "ANY"}

	asset := keyGen(q)

	if asset != "b78555bf3268be8a25d31ab80a47b6e9" {
		t.Error("invalid hash:", asset)
	}
}
func Test_unFqdn(t *testing.T) {

	q := "demo-domain.com."

	asset := unFqdn(q)

	if strings.HasSuffix(asset, ".") {
		t.Error("dot not removed dot in unFqdn func. asset:", asset)
	}
}

func Test_upperName(t *testing.T) {

	qlist := []struct {
		Asset  string
		Expect string
	}{
		{"demo-domain.com", "com"},
		{"demo-domain.com.tr", "com.tr"},
		{"go.istanbul", "istanbul"},
	}

	for _, e := range qlist {

		if u := upperName(e.Asset); u != e.Expect {
			t.Errorf("unexpected value. asset: %s, expect: %s, value: %s", e.Asset, e.Expect, u)
		}
	}
}
