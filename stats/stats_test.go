package stats

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBlocked(t *testing.T) {
	now := time.Date(2026, 1, 31, 12, 0, 0, 0, time.UTC)
	b := New(30 * 24 * time.Hour)

	b.Record("old.com", now.Add(-40*24*time.Hour))
	b.Record("month.com", now.Add(-10*24*time.Hour))
	b.Record("month.com", now.Add(-9*24*time.Hour))
	b.Record("month.com", now.Add(-8*24*time.Hour))
	b.Record("a.com", now.Add(-2*time.Hour))
	b.Record("b.com", now.Add(-1*time.Hour))
	b.Record("a.com", now)

	// old.com is past retention and pruned
	assert.Len(t, b.buckets, 6)

	recent := b.Recent(now, 24*time.Hour, 0)
	assert.Equal(t, []DomainCount{
		{Domain: "a.com", Count: 2, LastSeen: now},
		{Domain: "b.com", Count: 1, LastSeen: now.Add(-1 * time.Hour)},
	}, recent)

	// The 2h old a.com hit falls outside the last hour
	lastHour := b.Recent(now, time.Hour, 0)
	assert.Equal(t, []DomainCount{
		{Domain: "a.com", Count: 1, LastSeen: now},
		{Domain: "b.com", Count: 1, LastSeen: now.Add(-1 * time.Hour)},
	}, lastHour)

	top := b.Top(now, 30*24*time.Hour, 2)
	assert.Equal(t, "month.com", top[0].Domain)
	assert.Equal(t, 3, top[0].Count)
	assert.Equal(t, "a.com", top[1].Domain)
	assert.Len(t, top, 2)
}
