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

	"github.com/semihalev/log"
)

var timesSeen = make(map[string]int)
var whitelist = make(map[string]bool)

func updateBlocklist() error {
	if _, err := os.Stat("sources"); os.IsNotExist(err) {
		if err := os.Mkdir("sources", 0700); err != nil {
			return fmt.Errorf("error creating sources directory: %s", err)
		}
	}

	for _, entry := range Config.Whitelist {
		whitelist[entry] = true
	}

	for _, entry := range Config.Blocklist {
		blockCache.Set(entry, true)
	}

	if err := fetchSources(); err != nil {
		return fmt.Errorf("error fetching sources: %s", err)
	}

	return nil
}

func downloadBlocklist(uri string, name string) error {
	filePath := filepath.FromSlash(fmt.Sprintf("sources/%s", name))

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

func fetchSources() error {
	var wg sync.WaitGroup

	for _, uri := range Config.Sources {
		wg.Add(1)

		u, _ := url.Parse(uri)
		host := u.Host
		timesSeen[host] = timesSeen[host] + 1
		fileName := fmt.Sprintf("%s.%d.list", host, timesSeen[host])

		go func(uri string, name string) {
			log.Info("Fetching source", "uri", uri)
			if err := downloadBlocklist(uri, name); err != nil {
				fmt.Println(err)
			}

			wg.Done()
		}(uri, fileName)
	}

	wg.Wait()

	return nil
}

// UpdateBlockCache updates the BlockCache
func UpdateBlockCache() error {
	log.Info("Loading blocked domains from sources", "sources", len(Config.SourceDirs))

	for _, dir := range Config.SourceDirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			log.Info("Path not found, skipping...", "path", dir)
			continue
		}

		err := filepath.Walk(dir, func(path string, f os.FileInfo, _ error) error {
			if !f.IsDir() {
				file, err := os.Open(filepath.FromSlash(path))
				if err != nil {
					return fmt.Errorf("error opening file: %s", err)
				}
				defer file.Close()

				if err = parseHostFile(file); err != nil {
					return fmt.Errorf("error parsing hostfile %s", err)
				}
			}

			return nil
		})

		if err != nil {
			return fmt.Errorf("error walking location %s", err)
		}
	}

	log.Info("Domains loaded from sources", "total", blockCache.Length())

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

			if !blockCache.Exists(line) && !whitelist[line] {
				blockCache.Set(line, true)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error scanning hostfile: %s", err)
	}

	return nil
}
