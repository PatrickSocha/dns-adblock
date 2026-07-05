package database

import (
	"dns-adblock/models"
	"fmt"
	"reflect"
	"sync"
	"testing"

	"time"

	"github.com/likexian/doh-go/dns"
	"github.com/stretchr/testify/assert"
)

func Test_addRecord(t *testing.T) {
	now := time.Now()
	ttl := 5 * time.Minute

	type testSetup struct {
		database          map[string]*models.Record
		blockListDatabase map[string]interface{}
	}

	type testInput struct {
		address     string
		queryType   dns.Type
		recordValue []string
	}
	tests := []struct {
		name        string
		setup       testSetup
		input       testInput
		expected    *models.Record
		expectedDB  map[string]*models.Record
		expectedErr bool
	}{
		{
			name: "Domain saved A record",
			setup: testSetup{
				database:          map[string]*models.Record{},
				blockListDatabase: map[string]interface{}{},
			},
			input: testInput{
				address:     "google.com",
				queryType:   dns.TypeA,
				recordValue: []string{"192.168.0.1"},
			},
			expected: &models.Record{
				ExpiresAt: now.Add(ttl),
				A:         []string{"192.168.0.1"},
			},
			expectedDB: map[string]*models.Record{
				"google.com": {
					ExpiresAt: now.Add(ttl),
					A:         []string{"192.168.0.1"},
				},
			},
			expectedErr: false,
		},
		{
			name: "Domain saved with AAAA record",
			setup: testSetup{
				database:          map[string]*models.Record{},
				blockListDatabase: map[string]interface{}{},
			},
			input: testInput{
				address:     "google.com",
				queryType:   dns.TypeAAAA,
				recordValue: []string{"::1"},
			},
			expected: &models.Record{
				ExpiresAt: now.Add(ttl),
				AAAA:      []string{"::1"},
			},
			expectedDB: map[string]*models.Record{
				"google.com": {
					ExpiresAt: now.Add(ttl),
					AAAA:      []string{"::1"},
				},
			},
			expectedErr: false,
		},
		{
			name: "Domain saved with MX record",
			setup: testSetup{
				database:          map[string]*models.Record{},
				blockListDatabase: map[string]interface{}{},
			},
			input: testInput{
				address:     "google.com",
				queryType:   dns.TypeMX,
				recordValue: []string{"mx.google.com"},
			},
			expected: &models.Record{
				ExpiresAt: now.Add(ttl),
				MX:        []string{"mx.google.com"},
			},
			expectedDB: map[string]*models.Record{
				"google.com": {
					ExpiresAt: now.Add(ttl),
					MX:        []string{"mx.google.com"},
				},
			},
			expectedErr: false,
		},
		{
			name: "Adding AAAA record alongside existing A record for same domain",
			setup: testSetup{
				database: map[string]*models.Record{
					"google.com": {
						ExpiresAt: now.Add(ttl),
						A:         []string{"192.168.0.1"},
					},
				},
				blockListDatabase: map[string]interface{}{},
			},
			input: testInput{
				address:     "google.com",
				queryType:   dns.TypeAAAA,
				recordValue: []string{"::1"},
			},
			expected: &models.Record{
				ExpiresAt: now.Add(ttl),
				A:         []string{"192.168.0.1"},
				AAAA:      []string{"::1"},
			},
			expectedDB: map[string]*models.Record{
				"google.com": {
					ExpiresAt: now.Add(ttl),
					A:         []string{"192.168.0.1"},
					AAAA:      []string{"::1"},
				},
			},
			expectedErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := &Database{
				TTL:               ttl,
				database:          tt.setup.database,
				dbMux:             &sync.RWMutex{},
				blockMux:          &sync.RWMutex{},
				blockListDatabase: tt.setup.blockListDatabase,
			}
			actual, err := db.AddRecord(now, tt.input.address, tt.input.queryType, tt.input.recordValue)
			if tt.expectedErr {
				assert.Error(t, err)
				return
			}
			assert.Equal(t, actual.ExpiresAt, tt.expected.ExpiresAt)
			assert.True(t, reflect.DeepEqual(actual, tt.expected), fmt.Sprintf("records do not match. actua: %v, expected: %v", actual, tt.expected))
			assert.True(t, reflect.DeepEqual(db.database, tt.expectedDB), "actual database does not match expected database state")
		})
	}
}

func Test_hasQueryType(t *testing.T) {
	type testInput struct {
		r         *models.Record
		queryType dns.Type
	}
	tests := []struct {
		name     string
		input    testInput
		expected bool
	}{
		{
			name: "No record present",
			input: testInput{
				r:         nil,
				queryType: dns.TypeA,
			},
			expected: false,
		},
		{
			name: "A records present",
			input: testInput{
				r:         &models.Record{A: []string{"1.1.1.1"}},
				queryType: dns.TypeA,
			},
			expected: true,
		},
		{
			name: "no A records",
			input: testInput{
				r:         &models.Record{A: []string{}},
				queryType: dns.TypeA,
			},
			expected: false,
		},
		{
			name: "AAAA records present",
			input: testInput{
				r:         &models.Record{AAAA: []string{"::1"}},
				queryType: dns.TypeAAAA,
			},
			expected: true,
		},
		{
			name: "no AAAA records",
			input: testInput{
				r:         &models.Record{AAAA: []string{}},
				queryType: dns.TypeAAAA,
			},
			expected: false,
		},
		{
			name: "NS records present",
			input: testInput{
				r:         &models.Record{NS: []string{"ns1.name.com"}},
				queryType: dns.TypeNS,
			},
			expected: true,
		},
		{
			name: "No NS records",
			input: testInput{
				r:         &models.Record{NS: []string{}},
				queryType: dns.TypeNS,
			},
			expected: false,
		},
		{
			name: "MX records present",
			input: testInput{
				r:         &models.Record{MX: []string{"mail.name.com"}},
				queryType: dns.TypeMX,
			},
			expected: true,
		},
		{
			name: "No MX records",
			input: testInput{
				r:         &models.Record{MX: []string{}},
				queryType: dns.TypeMX,
			},
			expected: false,
		},
		{
			name: "CNAME record present",
			input: testInput{
				r:         &models.Record{CNAME: "cname.example.com"},
				queryType: dns.TypeCNAME,
			},
			expected: true,
		},
		{
			name: "empty CNAME record",
			input: testInput{
				r:         &models.Record{CNAME: ""},
				queryType: dns.TypeCNAME,
			},
			expected: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := hasQueryType(tt.input.r, tt.input.queryType)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
