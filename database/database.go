package database

import (
	"errors"
	"sync"
	"time"

	"dumbdns/models"

	"github.com/likexian/doh-go/dns"
)

var (
	ErrNotFound = errors.New("not found")
)

type Database struct {
	TTL               time.Duration
	database          map[string]*models.Record
	dbMux             *sync.RWMutex
	blockMux          *sync.RWMutex
	blockListDatabase map[string]interface{}

	Config *models.Config
}

func Start(ttl time.Duration) *Database {
	db := &Database{
		TTL:               ttl,
		dbMux:             &sync.RWMutex{},
		blockMux:          &sync.RWMutex{},
		database:          map[string]*models.Record{},
		blockListDatabase: map[string]interface{}{},
	}

	return db
}

func (db *Database) GetRecord(address string, queryType dns.Type) (*models.Record, error) {
	// Check custom hosts file for host:ip mapping file
	// e.g: archive.is blocks CloudFlare DNS, so we add
	// a manual mapping to get around that.
	if ip, ok := db.Config.Hosts[address]; ok {
		return &models.Record{A: []string{ip}}, nil
	}

	db.blockMux.RLock()
	// Check if in block list
	if _, blocked := db.blockListDatabase[address]; blocked {
		db.blockMux.RUnlock()
		return &models.Record{
			A:     []string{"127.0.0.1"},
			AAAA:  []string{"::1"},
			NS:    []string{"localhost"},
			MX:    []string{"localhost"},
			SRV:   []string{"_http._tcp.local."},
			CNAME: "localhost",
		}, nil
	}
	db.blockMux.RUnlock()

	// Now we can safely lock the database for record checking
	db.dbMux.RLock()
	record, ok := db.database[address]
	db.dbMux.RUnlock() // Immediately unlock the read.
	if ok {
		// Expired record, delete and return not found
		if time.Now().After(record.ExpiresAt) {
			db.dbMux.Lock() // Now acquire the write lock
			delete(db.database, address)
			db.dbMux.Unlock() // Unlock the write lock after deleting
			return nil, ErrNotFound
		}

		if hasQueryType(record, queryType) {
			return record, nil
		}
	}

	return nil, ErrNotFound
}

func hasQueryType(r *models.Record, queryType dns.Type) bool {
	if r == nil {
		return false
	}

	switch queryType {
	case dns.TypeA:
		return len(r.A) > 0
	case dns.TypeAAAA:
		return len(r.AAAA) > 0
	case dns.TypeNS:
		return len(r.NS) > 0
	case dns.TypeMX:
		return len(r.MX) > 0
	case dns.TypeTXT:
		return len(r.TXT) > 0
	case dns.TypeSOA:
		return r.SOA != ""
	case dns.TypePTR:
		return len(r.PTR) > 0
	case models.TypeSRV:
		return len(r.SRV) > 0
	case models.TypeKX:
		return len(r.KX) > 0
	case models.TypeSVCB:
		return len(r.SVCB) > 0
	case models.TypeHTTPS:
		return len(r.HTTPS) > 0
	case dns.TypeCNAME:
		return r.CNAME != ""
	default:
		return false
	}
}

func (db *Database) AddRecord(now time.Time, address string, queryType dns.Type, recordValue []string) (*models.Record, error) {
	db.dbMux.RLock()
	defer db.dbMux.RUnlock()
	record, ok := db.database[address]
	if !ok {
		// We create a new record to be populated
		record = &models.Record{}
	}

	switch queryType {
	case dns.TypeA:
		record.A = recordValue
	case dns.TypeAAAA:
		record.AAAA = recordValue
	case dns.TypeNS:
		record.NS = recordValue
	case dns.TypeMX:
		record.MX = recordValue
	case dns.TypeTXT:
		record.TXT = recordValue
	case dns.TypeSOA:
		if len(recordValue) == 1 {
			record.SOA = recordValue[0]
		}
	case dns.TypePTR:
		record.PTR = recordValue
	case models.TypeSRV:
		record.SRV = recordValue
	case models.TypeKX:
		record.KX = recordValue
	case models.TypeSVCB:
		record.SVCB = recordValue
	case models.TypeHTTPS:
		record.HTTPS = recordValue
	case dns.TypeCNAME:
		if len(recordValue) == 1 {
			record.CNAME = recordValue[0]
		}
	default:
		return nil, errors.New("could not update value for query type")
	}

	if record.ExpiresAt.IsZero() {
		record.ExpiresAt = now.Add(db.TTL)
	}

	db.database[address] = record

	return record, nil
}
