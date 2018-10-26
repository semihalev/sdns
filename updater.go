package main

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/semihalev/log"
)

var timesSeen = make(map[string]int)
var whitelist = make(map[string]bool)

func updateBlocklists(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := os.Mkdir(path, 0755); err != nil {
			return fmt.Errorf("error creating sources directory: %s", err)
		}
	}

	for _, entry := range Config.Whitelist {
		whitelist[dns.Fqdn(entry)] = true
	}

	for _, entry := range Config.Blocklist {
		BlockList.Set(dns.Fqdn(entry), true)
	}

	fetchBlocklist(path)

	return nil
}

func downloadBlocklist(uri, path, name string) error {
	filePath := filepath.FromSlash(fmt.Sprintf("%s/%s", path, name))

	output, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("error creating file: %s", err)
	}
	defer output.Close()

	response, err := http.Get(uri)
	if err != nil {
		return fmt.Errorf("error downloading source: %s", err)
	}
	defer response.Body.Close()

	if _, err := io.Copy(output, response.Body); err != nil {
		return fmt.Errorf("error copying output: %s", err)
	}

	return nil
}

func fetchBlocklist(path string) {
	var wg sync.WaitGroup

	for _, uri := range Config.BlockLists {
		wg.Add(1)

		u, _ := url.Parse(uri)
		host := u.Host
		timesSeen[host] = timesSeen[host] + 1
		fileName := fmt.Sprintf("%s.%d.tmp", host, timesSeen[host])

		go func(uri string, name string) {
			log.Info("Fetching blacklist", "uri", uri)
			if err := downloadBlocklist(uri, path, name); err != nil {
				log.Error("Fetching blacklist", "uri", uri, "error", err.Error())
			}

			wg.Done()
		}(uri, fileName)
	}

	wg.Wait()
}

func readBlocklists(dir string) error {
	log.Info("Loading blocked domains", "dir", dir)

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		log.Warn("Path not found, skipping...", "path", dir)
		return nil
	}

	err := filepath.Walk(dir, func(path string, f os.FileInfo, _ error) error {
		if !f.IsDir() {
			file, err := os.Open(filepath.FromSlash(path))
			if err != nil {
				return fmt.Errorf("error opening file: %s", err)
			}

			if err = parseHostFile(file); err != nil {
				file.Close()
				return fmt.Errorf("error parsing hostfile %s", err)
			}

			file.Close()

			if filepath.Ext(path) == ".tmp" {
				os.Remove(filepath.FromSlash(path))
			}
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("error walking location %s", err)
	}

	log.Info("Blocked domains loaded", "total", BlockList.Length())

	return nil
}

func parseHostFile(file *os.File) error {
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		isComment := strings.HasPrefix(line, "#")

		if !isComment && line != "" {
			fields := strings.Fields(line)

			if len(fields) > 1 && !strings.HasPrefix(fields[1], "#") {
				line = fields[1]
			} else {
				line = fields[0]
			}

			line = dns.Fqdn(line)

			if !BlockList.Exists(line) && !whitelist[line] {
				BlockList.Set(line, true)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error scanning hostfile: %s", err)
	}

	return nil
}
