package dnsClient

import (
	"context"
	"dns-adblock/models"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"dns-adblock/database"
	"dns-adblock/dohClient"

	dohDns "github.com/likexian/doh-go/dns"
	"github.com/miekg/dns"
)

type DnsServer struct {
	DnsServer *dns.Server
	dohClient *dohClient.DohClient
	db        *database.Database

	refreshFreq time.Duration
}

func Start(port string, dohClient *dohClient.DohClient, db *database.Database) (*DnsServer, error) {
	d := &DnsServer{
		dohClient: dohClient,
		db:        db,
	}

	dns.HandleFunc(".", d.handleDnsRequest)
	d.DnsServer = &dns.Server{Addr: port, Net: "udp"}

	log.Printf("Starting DNS-AdBlock at %s\n", d.DnsServer.Addr)
	err := d.DnsServer.ListenAndServe()
	if err != nil {
		return nil, fmt.Errorf("error starting service: %w", err)
	}

	return d, nil
}

func (d *DnsServer) handleDnsRequest(w dns.ResponseWriter, r *dns.Msg) {
	cleanIP := strings.Split(w.RemoteAddr().String(), ":")
	ip := net.ParseIP(cleanIP[0])
	if !(ip.IsPrivate() || ip.IsLoopback()) {
		w.Close()
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false
	switch r.Opcode {
	case dns.OpcodeQuery:
		d.ParseQuery(ctx, m)
	}

	err := w.WriteMsg(m)
	if err != nil {
		fmt.Errorf("error writing response message: %w", err)
	}
}

func (d *DnsServer) ParseQuery(ctx context.Context, m *dns.Msg) {
	for _, q := range m.Question {
		queryType, err := models.QueryToDoHType(q.Qtype)
		if err != nil {
			log.Printf("error getting query type: %v", err)
			m.SetRcode(m, dns.RcodeServerFailure)
			continue
		}

		records, err := d.getRecords(ctx, q.Name, queryType)
		if err != nil {
			log.Printf("error fetching records for %s: %v", q.Name, err)
			m.SetRcode(m, dns.RcodeServerFailure)
			continue
		}

		switch q.Qtype {
		case dns.TypeA:
			for _, v := range records.A {
				rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, v))
				if err != nil {
					log.Printf("error generating A record: %v", err)
					continue
				}
				m.Answer = append(m.Answer, rr)
			}
		case dns.TypeAAAA:
			for _, v := range records.AAAA {
				rr, err := dns.NewRR(fmt.Sprintf("%s AAAA %s", q.Name, v))
				if err != nil {
					log.Printf("error generating AAAA record: %v", err)
					continue
				}
				m.Answer = append(m.Answer, rr)
			}
		case dns.TypeMX:
			for _, v := range records.MX {
				rr, err := dns.NewRR(fmt.Sprintf("%s MX %s", q.Name, v))
				if err != nil {
					log.Printf("error generating MX record: %v", err)
					continue
				}
				m.Answer = append(m.Answer, rr)
			}
		case dns.TypeCNAME:
			if records.CNAME == "" {
				continue
			}
			rr, err := dns.NewRR(fmt.Sprintf("%s IN CNAME %s", q.Name, records.CNAME))
			if err != nil {
				log.Printf("error generating CNAME record: %v", err)
				continue
			}
			m.Answer = append(m.Answer, rr)
		case dns.TypeNS:
			for _, v := range records.NS {
				rr, err := dns.NewRR(fmt.Sprintf("%s NS %s", q.Name, v))
				if err != nil {
					log.Printf("error generating NS record: %v", err)
					continue
				}
				m.Answer = append(m.Answer, rr)
			}
		case dns.TypeTXT:
			for _, v := range records.TXT {
				rr, err := dns.NewRR(fmt.Sprintf("%s TXT %s", q.Name, v))
				if err != nil {
					log.Printf("error generating TXT record: %v", err)
					continue
				}
				m.Answer = append(m.Answer, rr)
			}
		case dns.TypeSOA:
			if records.SOA == "" {
				continue
			}
			rr, err := dns.NewRR(fmt.Sprintf("%s SOA %s", q.Name, records.SOA))
			if err != nil {
				log.Printf("error generating SOA record: %v", err)
				continue
			}
			m.Answer = append(m.Answer, rr)
		case dns.TypePTR:
			for _, v := range records.PTR {
				rr, err := dns.NewRR(fmt.Sprintf("%s PTR %s", q.Name, v))
				if err != nil {
					log.Printf("error generating PTR record: %v", err)
					continue
				}
				m.Answer = append(m.Answer, rr)
			}
		case dns.TypeSRV:
			for _, v := range records.SRV {
				rr, err := dns.NewRR(fmt.Sprintf("%s SRV %s", q.Name, v))
				if err != nil {
					log.Printf("error generating SRV record for %s with data %q: %v", q.Name, v, err)
					continue
				}
				m.Answer = append(m.Answer, rr)
			}
		case dns.TypeKX:
			for _, v := range records.KX {
				rr, err := dns.NewRR(fmt.Sprintf("%s KX %s", q.Name, v))
				if err != nil {
					log.Printf("error generating KX record: %v", err)
					continue
				}
				m.Answer = append(m.Answer, rr)
			}
		case dns.TypeSVCB:
			for _, v := range records.SVCB {
				rr, err := dns.NewRR(fmt.Sprintf("%s SVCB %s", q.Name, v))
				if err != nil {
					log.Printf("error generating SVCB record: %v", err)
					continue
				}
				m.Answer = append(m.Answer, rr)
			}
		case dns.TypeHTTPS:
			for _, v := range records.HTTPS {
				rr, err := dns.NewRR(fmt.Sprintf("%s HTTPS %s", q.Name, v))
				if err != nil {
					log.Printf("error generating HTTPS record: %v", err)
					continue
				}
				m.Answer = append(m.Answer, rr)
			}
		}
	}
}

func (d *DnsServer) getRecords(ctx context.Context, address string, queryType dohDns.Type) (*models.Record, error) {
	// remove the "." from the end of the passed in address (google.com.)
	address = address[:len(address)-1]

	record, err := d.db.GetRecord(address, queryType)
	if errors.Is(err, database.ErrNotFound) {
		resp, queryErr := d.dohClient.QueryAuthority(ctx, address, queryType)
		// If query fails, return error without caching
		if queryErr != nil {
			return record, fmt.Errorf("error querying authority: %w", queryErr)
		}

		// Even if resp is empty, this is a valid DNS response (NOERROR with no answers)
		// Cache it so we don't repeatedly query for the same missing record
		now := time.Now().UTC()
		record, addErr := d.db.AddRecord(now, address, queryType, resp)
		if addErr != nil {
			return record, fmt.Errorf("error adding record: %w", addErr)
		}

		return record, nil
	}

	return record, nil
}
