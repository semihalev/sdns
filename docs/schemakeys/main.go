// Command schemakeys prints every TOML key the configuration parser accepts,
// walked from the root config.Config type by reflection.
//
// Reflection rather than a scan of the source: the decoder matches an untagged
// field on its lowercased name, so a scan for `toml:"..."` tags reports keys
// like Plugin.Path as absent and passes. Asking the type itself cannot drift
// from what the parser does, which is the whole point of the check that runs
// this.
package main

import (
	"encoding"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/semihalev/sdns/config"
)

// A type that decodes itself from text is a scalar to the parser, whatever
// fields it happens to have. config.Duration is a struct wrapping
// time.Duration; without this the walk would emit "duration" as though it
// were a key operators could write.
var textUnmarshaler = reflect.TypeOf((*encoding.TextUnmarshaler)(nil)).Elem()

func scalar(t reflect.Type) bool {
	return t.Implements(textUnmarshaler) || reflect.PointerTo(t).Implements(textUnmarshaler)
}

func main() {
	seen := map[string]bool{}
	walk(reflect.TypeOf(config.Config{}), "", seen)

	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Println(strings.Join(keys, "\n"))
}

// prefix carries the dotted path of the table this struct sits in. Without it
// every section's "enabled" collapsed onto one key, and deleting the row for
// any one of rpz/ecs/dns64/kubernetes left the check green.
func walk(t reflect.Type, prefix string, out map[string]bool) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct || scalar(t) {
		return
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" { // unexported
			continue
		}
		name := f.Tag.Get("toml")
		if name == "-" {
			continue
		}
		if idx := strings.Index(name, ","); idx >= 0 {
			name = name[:idx]
		}
		if name == "" {
			// What the decoder falls back to: a case-insensitive match on the
			// field name.
			name = strings.ToLower(f.Name)
		}
		path := prefix + name

		ft := f.Type
		if scalar(ft) {
			out[path] = true
			continue
		}
		for ft.Kind() == reflect.Pointer || ft.Kind() == reflect.Slice ||
			ft.Kind() == reflect.Array || ft.Kind() == reflect.Map {
			ft = ft.Elem()
		}
		// A field that opens a table is a heading, not a setting an operator
		// assigns to, only its leaves are keys.
		if ft.Kind() == reflect.Struct && !scalar(ft) {
			walk(ft, path+".", out)
			continue
		}
		out[path] = true
	}
}
