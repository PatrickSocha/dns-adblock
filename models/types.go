package models

import (
	"fmt"
	"time"

	dohDns "github.com/likexian/doh-go/dns"
	"github.com/miekg/dns"
)

var (
	// TypeSRV is a custom DNS type for Service Records
	// Defined here because doh-go doesn't have built-in SRV support
	TypeSRV = dohDns.Type("SRV")
	// TypeKX is a custom DNS type for Key eXchange records
	// Defined here because doh-go doesn't have built-in KX support
	TypeKX = dohDns.Type("KX")
	// TypeSVCB is a custom DNS type for Service Binding records
	// Defined here because doh-go doesn't have built-in SVCB support
	TypeSVCB = dohDns.Type("SVCB")
	// TypeHTTPS is a custom DNS type for HTTPS records
	// Defined here because doh-go doesn't have built-in HTTPS support
	TypeHTTPS = dohDns.Type("HTTPS")
)

// QueryToDoHType converts miekg/dns query types to doh-go types
func QueryToDoHType(t uint16) (dohDns.Type, error) {
	switch t {
	case dns.TypeA:
		return dohDns.TypeA, nil
	case dns.TypeAAAA:
		return dohDns.TypeAAAA, nil
	case dns.TypeMX:
		return dohDns.TypeMX, nil
	case dns.TypeCNAME:
		return dohDns.TypeCNAME, nil
	case dns.TypeNS:
		return dohDns.TypeNS, nil
	case dns.TypeTXT:
		return dohDns.TypeTXT, nil
	case dns.TypeSOA:
		return dohDns.TypeSOA, nil
	case dns.TypePTR:
		return dohDns.TypePTR, nil
	case dns.TypeSRV:
		return TypeSRV, nil
	case dns.TypeKX:
		return TypeKX, nil
	case dns.TypeSVCB:
		return TypeSVCB, nil
	case dns.TypeHTTPS:
		return TypeHTTPS, nil

	default:
		return "", fmt.Errorf("query type not supported: %s", dns.Type(t).String())
	}
}

// Record represents a DNS record with multiple supported types
type Record struct {
	ExpiresAt time.Time

	A      []string
	AAAA   []string
	NS     []string
	MX     []string
	SRV    []string
	TXT    []string
	CNAME  string
	SOA    string
	PTR    []string
	KX     []string
	SVCB   []string
	HTTPS  []string
}
