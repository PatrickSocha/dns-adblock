package main

import (
	"log"
	"time"

	"dns-adblock/admin"
	"dns-adblock/database"
	dnsServer "dns-adblock/dns"
	"dns-adblock/dohClient"
	"dns-adblock/stats"

	dohGo "github.com/likexian/doh-go"
)

const (
	port                 = ":53"
	blockListRefreshRate = 2 * time.Hour
	cacheTTL             = 5 * time.Minute
	statsRetention       = 30 * 24 * time.Hour
)

func main() {
	doh := dohClient.Start(dohGo.Quad9Provider, dohGo.CloudflareProvider)
	defer doh.Doh.Close()

	db := database.Start(cacheTTL)
	if err := db.LoadConfig(); err != nil {
		log.Fatalf("error reading config: %v", err)
	}
	go db.UpdateBlockList(blockListRefreshRate)

	if db.Config.AdminAddr != "" {
		db.Blocked = stats.New(statsRetention)
		admin.Start(db.Config.AdminAddr, db)
	}

	server, err := dnsServer.Start(port, doh, db)
	if err != nil {
		log.Fatalf("Failed to start service: %s\n ", err.Error())
	}

	defer func() {
		if r := recover(); r != nil {
			log.Printf("recovered error: %v", r)
		}
	}()

	defer server.DnsServer.Shutdown()
}
