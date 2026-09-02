package debugenv

import "testing"

func TestUnsetSwitchIsOff(t *testing.T) {
	if on("SDNS_SWITCH_NOBODY_SET") {
		t.Fatal("an unset switch reported on")
	}
}

// The switch reads a boolean, not mere presence. "false" is the case that
// matters: it used to turn the surface on, which is the opposite of what the
// operator who typed it asked for.
func TestSwitchNeedsABooleanNotMerePresence(t *testing.T) {
	for name, want := range map[string]bool{
		"empty": false,
		"false": false,
		"FALSE": false,
		"0":     false,
		"yes":   false,
		"on":    false,
		"true":  true,
		"TRUE":  true,
		"1":     true,
		"t":     true,
	} {
		value := name
		if name == "empty" {
			value = ""
		}
		t.Run(name, func(t *testing.T) {
			t.Setenv("SDNS_PPROF", value)
			if got := PProf(); got != want {
				t.Fatalf("SDNS_PPROF=%q: PProf() = %v, want %v", value, got, want)
			}
		})
	}
}

// Each switch answers for its own variable. The two must not collapse onto
// one name, which is the way a shared helper would fail silently.
func TestSwitchesReadTheirOwnVariable(t *testing.T) {
	t.Setenv("SDNS_PPROF", "true")
	t.Setenv("SDNS_DEBUGNS", "false")

	if !PProf() {
		t.Error("PProf() = false with SDNS_PPROF=true")
	}
	if DebugNS() {
		t.Error("DebugNS() = true with SDNS_DEBUGNS=false")
	}

	t.Setenv("SDNS_PPROF", "false")
	t.Setenv("SDNS_DEBUGNS", "true")

	if PProf() {
		t.Error("PProf() = true with SDNS_PPROF=false")
	}
	if !DebugNS() {
		t.Error("DebugNS() = false with SDNS_DEBUGNS=true")
	}
}
