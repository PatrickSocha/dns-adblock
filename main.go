package main

import (
	"log"
	"time"

	"dns-adblock/database"
	dnsServer "dns-adblock/dns"
	"dns-adblock/dohClient"

	dohGo "github.com/likexian/doh-go"
)

const (
	port                 = ":53"
	blockListRefreshRate = 2 * time.Hour
	cacheTTL             = 5 * time.Minute
)

func main() {
	doh := dohClient.Start(dohGo.Quad9Provider, dohGo.CloudflareProvider)
	defer doh.Doh.Close()

	db := database.Start(cacheTTL)
	go db.UpdateBlockList(blockListRefreshRate)

	server, err := dnsServer.Start(port, doh, db)
	if err != nil {
		log.Fatalf("Failed to start service: %s\n ", err.Error())
	}

	defer func() {
		if r := recover(); r != nil {
			log.Println("recovered error:\n%w", err)
		}
	}()

	defer server.DnsServer.Shutdown()
}
