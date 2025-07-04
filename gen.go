//go:build ignore

package main

import (
	"bytes"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"text/template"

	"github.com/semihalev/zlog"
)

// middleware list order very important, handlers call via this order.
var middlewareList = []string{
	"recovery",
	"loop",
	"metrics",
	"dnstap",
	"accesslist",
	"ratelimit",
	"edns",
	"accesslog",
	"chaos",
	"hostsfile",
	"blocklist",
	"as112",
	"kubernetes",
	"cache",
	"failover",
	"resolver",
	"forwarder",
}

const codeTemplate = `// Code generated by gen.go DO NOT EDIT.

package main

import (
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
{{range .Imports}}
	"{{.}}"
{{- end}}
)

func init() {
{{range .Middleware}}	middleware.Register("{{.}}", func(cfg *config.Config) middleware.Handler { return {{.}}.New(cfg) })
{{end -}}
}
`

func main() {
	if err := generate(); err != nil {
		zlog.Fatal("Generation failed", "error", err.Error())
	}
}

func generate() error {
	// Validate middleware directories
	var imports []string
	for _, name := range middlewareList {
		dir := filepath.Join(middlewareDir, name)
		stat, err := os.Stat(dir)
		if err != nil {
			return fmt.Errorf("checking middleware %s: %w", name, err)
		}
		if !stat.IsDir() {
			return fmt.Errorf("%s is not a directory", dir)
		}
		imports = append(imports, filepath.Join(prefixDir, middlewareDir, name))
	}

	// Generate code using template
	tmpl, err := template.New("code").Parse(codeTemplate)
	if err != nil {
		return fmt.Errorf("parsing template: %w", err)
	}

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, struct {
		Imports    []string
		Middleware []string
	}{
		Imports:    imports,
		Middleware: middlewareList,
	})
	if err != nil {
		return fmt.Errorf("executing template: %w", err)
	}

	// Format the generated code
	formatted, err := format.Source(buf.Bytes())
	if err != nil {
		return fmt.Errorf("formatting code: %w", err)
	}

	// Write to file
	err = os.WriteFile(filename, formatted, 0644)
	if err != nil {
		return fmt.Errorf("writing file: %w", err)
	}

	fmt.Printf("Generated %s successfully\n", filename)
	return nil
}

const (
	filename      = "registry.go"
	prefixDir     = "github.com/semihalev/sdns"
	middlewareDir = "middleware"
)
