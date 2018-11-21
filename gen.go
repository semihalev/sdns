//+build ignore

package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// handler list order very important, call handlers via this order.
var handlerList = []string{
	"recovery",
	"metrics",
	"accesslist",
	"ratelimit",
	"edns",
	"hostsfile",
	"blocklist",
	"cache",
	"resolver",
}

func main() {
	var pathlist []string
	for _, name := range handlerList {
		stat, err := os.Stat(filepath.Join(middlewareDir, name))
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		if !stat.IsDir() {
			fmt.Println("path is not directory")
			os.Exit(1)
		}
		pathlist = append(pathlist, filepath.Join(prefixDir, middlewareDir, name))
	}

	file, err := os.Create(filename)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	defer file.Close()

	file.WriteString("// Code generated by gen.go DO NOT EDIT.\n")

	file.WriteString("\npackage main\n\nimport (\n")

	for _, path := range pathlist {
		file.WriteString("\t_ \"" + path + "\"\n")
	}

	file.WriteString(")")
}

const (
	filename      = "generated.go"
	prefixDir     = "github.com/semihalev/sdns"
	middlewareDir = "middleware"
)
