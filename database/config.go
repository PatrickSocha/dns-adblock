package database

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"dns-adblock/models"
)

const configFile = "dns-adblock.json"

type fileConfig struct {
	AdminAddr        string            `json:"adminAddr,omitempty"`
	BlockLists       []models.Sources  `json:"blockLists"`
	WhitelistDomains []string          `json:"whitelist"`
	Hosts            map[string]string `json:"hostsFile"`
}

// findConfig returns the config path, checking the working directory then
// the executable's directory.
func findConfig() string {
	if _, err := os.Stat(configFile); err == nil {
		return configFile
	}

	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("error getting executable path: %v", err)
	}
	return filepath.Join(filepath.Dir(exePath), configFile)
}

func readConfigFile(path string) (*fileConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("could not open config file: %w", err)
	}
	defer file.Close()

	config := &fileConfig{}
	err = json.NewDecoder(file).Decode(config)
	if err != nil {
		return nil, fmt.Errorf("error decoding JSON: %w", err)
	}
	return config, nil
}

func writeConfigFile(path string, config *fileConfig) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".dns-adblock-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	enc := json.NewEncoder(tmp)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(config); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func (db *Database) LoadConfig() error {
	path := findConfig()
	config, err := readConfigFile(path)
	if err != nil {
		return err
	}

	domainMap := make(map[string]interface{})
	for _, domain := range config.WhitelistDomains {
		domainMap[domain] = struct{}{}
	}

	db.configPath = path
	db.Config = &models.Config{
		Blocklists:       config.BlockLists,
		WhitelistDomains: domainMap,
		Hosts:            config.Hosts,
		AdminAddr:        config.AdminAddr,
	}
	return nil
}

func (db *Database) IsWhitelisted(domain string) bool {
	db.blockMux.RLock()
	defer db.blockMux.RUnlock()

	_, ok := db.Config.WhitelistDomains[domain]
	return ok
}

// AddWhitelist whitelists the domain immediately and saves it to the config file.
func (db *Database) AddWhitelist(domain string) error {
	db.blockMux.Lock()
	defer db.blockMux.Unlock()

	if _, ok := db.Config.WhitelistDomains[domain]; ok {
		return nil
	}
	db.Config.WhitelistDomains[domain] = struct{}{}

	// Re-read the file so any manual edits since startup are kept
	config, err := readConfigFile(db.configPath)
	if err != nil {
		return err
	}
	config.WhitelistDomains = append(config.WhitelistDomains, domain)
	if err := writeConfigFile(db.configPath, config); err != nil {
		return fmt.Errorf("error saving config: %w", err)
	}

	log.Printf("Whitelisted %s", domain)
	return nil
}
