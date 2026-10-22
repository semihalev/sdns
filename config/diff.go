package config

import (
	"encoding"
	"reflect"
	"slices"
	"strings"
)

// meaning compares keys whose written form has more than one spelling of
// the same value: an unset pointer is the documented default.
var meaning = map[string]func(*Config) any{
	"rfc8198": func(c *Config) any { return c.RFC8198Enabled() },
	"rfc9520": func(c *Config) any { return c.RFC9520Enabled() },
}

// ignored keys are parsed for old files' sake and carry no setting.
var ignored = map[string]bool{"version": true}

var textUnmarshaler = reflect.TypeFor[encoding.TextUnmarshaler]()

// ChangedKeys lists, sorted, the keys whose value differs between old and
// next, named as the file names them: dotted inside a table, and a list or
// an array of tables as a whole under its own key.
func ChangedKeys(old, next *Config) []string {
	var keys []string
	diff(reflect.ValueOf(old).Elem(), reflect.ValueOf(next).Elem(), "", old, next, &keys)
	slices.Sort(keys)
	return keys
}

func diff(a, b reflect.Value, prefix string, old, next *Config, keys *[]string) {
	t := a.Type()
	for i := range t.NumField() {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("toml"), ",")
		if name == "-" {
			continue
		}
		if name == "" {
			name = strings.ToLower(f.Name)
		}
		key := prefix + name
		if ignored[key] {
			continue
		}
		if same, ok := meaning[key]; ok {
			if same(old) != same(next) {
				*keys = append(*keys, key)
			}
			continue
		}
		fa, fb := a.Field(i), b.Field(i)
		if table(f.Type) {
			diff(fa, fb, key+".", old, next, keys)
			continue
		}
		if !reflect.DeepEqual(fa.Interface(), fb.Interface()) {
			*keys = append(*keys, key)
		}
	}
}

// table reports a struct the file writes as a table of keys, rather than
// a value that decodes itself from text.
func table(t reflect.Type) bool {
	return t.Kind() == reflect.Struct && !t.Implements(textUnmarshaler) &&
		!reflect.PointerTo(t).Implements(textUnmarshaler)
}
