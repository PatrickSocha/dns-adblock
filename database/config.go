package database

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"dns-adblock/models"
)

func readConfigFromDisk() (*models.Config, error) {
	configFile := "dns-adblock.json"
	file, err := os.Open("./" + configFile)
	if err != nil {
		exePath, err := os.Executable()
		if err != nil {
			log.Fatalf("error getting executable path: %v", err)
		}
		wd := filepath.Dir(exePath)

		fullPath := filepath.Join(wd, configFile)
		file, err = os.Open(fullPath)
		if err != nil {
			log.Fatalf("could not open file with full path: %v", err)
		}
	}
	defer file.Close()

	config := struct {
		BlockLists       []models.Sources  `json:"blockLists"`
		WhitelistDomains []string          `json:"whiteList"`
		Hosts            map[string]string `json:"hostsFile"`
	}{}
	
	err = json.NewDecoder(file).Decode(&config)
	if err != nil {
		return nil, fmt.Errorf("error decoding JSON: %w", err)
	}

	domainMap := make(map[string]interface{})
	for _, domain := range config.WhitelistDomains {
		domainMap[domain] = struct{}{}
	}

	return &models.Config{
		Blocklists:       config.BlockLists,
		WhitelistDomains: domainMap,
		Hosts:            config.Hosts,
	}, nil
}
