package blocklist

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
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/log"
)

var timesSeen = make(map[string]int)
var whitelist = make(map[string]bool)

func (b *BlockList) fetchBlocklists() {
	timer := time.NewTimer(time.Second)

	if b.cfg.BlockListDir == "" {
		b.cfg.BlockListDir = "."
	}

	<-timer.C

	if err := b.updateBlocklists(); err != nil {
		log.Error("Update blocklists failed", "error", err.Error())
	}

	if err := b.readBlocklists(); err != nil {
		log.Error("Read blocklists failed", "dir", b.cfg.BlockListDir, "error", err.Error())
	}
}

func (b *BlockList) updateBlocklists() error {
	if _, err := os.Stat(b.cfg.BlockListDir); os.IsNotExist(err) {
		if err := os.Mkdir(b.cfg.BlockListDir, 0750); err != nil {
			return fmt.Errorf("error creating sources directory: %s", err)
		}
	}

	for _, entry := range b.cfg.Whitelist {
		whitelist[dns.Fqdn(entry)] = true
	}

	for _, entry := range b.cfg.Blocklist {
		b.Set(dns.Fqdn(entry))
	}

	b.fetchBlocklist()

	return nil
}

func (b *BlockList) downloadBlocklist(uri, name string) error {
	filePath := filepath.FromSlash(fmt.Sprintf("%s/%s", b.cfg.BlockListDir, name))

	output, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("error creating file: %s", err)
	}

	defer func() {
		err := output.Close()
		if err != nil {
			log.Warn("Blocklist file close failed", "name", name, "error", err.Error())
		}
	}()

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

func (b *BlockList) fetchBlocklist() {
	var wg sync.WaitGroup

	for _, uri := range b.cfg.BlockLists {
		wg.Add(1)

		u, _ := url.Parse(uri)
		host := u.Host
		timesSeen[host] = timesSeen[host] + 1
		fileName := fmt.Sprintf("%s.%d.tmp", host, timesSeen[host])

		go func(uri string, name string) {
			log.Info("Fetching blacklist", "uri", uri)
			if err := b.downloadBlocklist(uri, name); err != nil {
				log.Error("Fetching blacklist", "uri", uri, "error", err.Error())
			}

			wg.Done()
		}(uri, fileName)
	}

	wg.Wait()
}

func (b *BlockList) readBlocklists() error {
	log.Info("Loading blocked domains", "path", b.cfg.BlockListDir)

	if _, err := os.Stat(b.cfg.BlockListDir); os.IsNotExist(err) {
		log.Warn("Path not found, skipping...", "path", b.cfg.BlockListDir)
		return nil
	}

	err := filepath.Walk(b.cfg.BlockListDir, func(path string, f os.FileInfo, _ error) error {
		if !f.IsDir() {
			file, err := os.Open(filepath.FromSlash(path))
			if err != nil {
				return fmt.Errorf("error opening file: %s", err)
			}

			if err = b.parseHostFile(file); err != nil {
				_ = file.Close()
				return fmt.Errorf("error parsing hostfile %s", err)
			}

			_ = file.Close()

			if filepath.Ext(path) == ".tmp" {
				_ = os.Remove(filepath.FromSlash(path))
			}
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("error walking location %s", err)
	}

	log.Info("Blocked domains loaded", "total", b.Length())

	return nil
}

func (b *BlockList) parseHostFile(file *os.File) error {
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

			if !b.Exists(line) && !whitelist[line] {
				b.Set(line)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error scanning hostfile: %s", err)
	}

	return nil
}
