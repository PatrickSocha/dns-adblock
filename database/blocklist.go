package database

import (
	"bufio"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"
)

func (db *Database) UpdateBlockList(refreshRate time.Duration) {
	config, err := readConfigFromDisk()
	if err != nil {
		log.Fatalf("error reading config: %v", err)
		return
	}
	db.Config = config

	for {
		log.Println("Getting block list")
		db.blockMux.Lock()
		db.blockListDatabase = make(map[string]interface{})
		db.wildcardBlockList = make(map[string]interface{})

		for _, s := range config.Blocklists {
			var compRegEx = regexp.MustCompile(s.Regex)
			resp, err := http.Get(s.Url)
			if err != nil {
				log.Println("Error:", err)
				continue
			}
			scanner := bufio.NewScanner(resp.Body)

			// populate the list
			for scanner.Scan() {
				v := getParams(compRegEx, scanner.Text())
				if v == nil {
					continue
				}
				if suffix, ok := strings.CutPrefix(*v, "*."); ok {
					db.wildcardBlockList[suffix] = struct{}{}
				} else {
					db.blockListDatabase[*v] = struct{}{}
				}
			}
			resp.Body.Close()
		}
		for domain, _ := range config.WhitelistDomains {
			delete(db.blockListDatabase, domain)
		}
		db.blockMux.Unlock()
		log.Printf("Block list updated with %d records and %d wildcards\r\n", len(db.blockListDatabase), len(db.wildcardBlockList))

		log.Println("Purging old database records")
		db.dbMux.Lock()
		for domain, v := range db.database {
			if time.Now().After(v.ExpiresAt) {
				delete(db.database, domain)
			}
		}
		db.dbMux.Unlock()

		log.Println("Refresh Go routine sleeping")
		time.Sleep(refreshRate)
	}
}

func getParams(compRegEx *regexp.Regexp, url string) *string {
	match := compRegEx.FindStringSubmatch(url)

	paramsMap := make(map[string]string)
	for i, name := range compRegEx.SubexpNames() {
		if i > 0 && i <= len(match) {
			paramsMap[name] = match[i]
		}
	}
	var domain *string
	if v, ok := paramsMap["url"]; ok {
		domain = &v
	}

	return domain
}
