// Package debugenv reads the environment switches that expose sdns's
// diagnostic surfaces. Each switch is named in exactly one place here, so the
// two readers of a switch cannot drift apart on either its spelling or its
// meaning.
package debugenv

import (
	"os"
	"strconv"
)

// on reports whether a switch is set to a value that asks for the surface.
//
// The documented spelling is a boolean, the README uses SDNS_DEBUGNS=true and
// the API guide uses SDNS_PPROF=1, so a boolean is what is read, and anything
// else leaves the surface off: unset, empty, "false", "0", or a word Go does
// not recognize. Presence alone used to be enough, which read an operator's
// explicit SDNS_PPROF=false as a request to publish pprof; the routes bypass
// the API's bearer token, so the failure was silent and in the wrong
// direction. Off is the safe answer to a value nobody can interpret.
func on(name string) bool {
	enabled, err := strconv.ParseBool(os.Getenv(name))
	return err == nil && enabled
}

// PProf reports whether the API should serve the net/http/pprof routes.
func PProf() bool { return on("SDNS_PPROF") }

// DebugNS reports whether the CHAOS-class nameserver debug view is served.
func DebugNS() bool { return on("SDNS_DEBUGNS") }
