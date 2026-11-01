package stats

import (
	"sort"
	"sync"
	"time"
)

// bucketSize is the time resolution of the stats, so windows are accurate to
// within a minute.
const bucketSize = time.Minute

// Blocked counts blocked domains in per-minute buckets, held in memory only.
// Buckets older than the retention period are dropped.
type Blocked struct {
	mu        sync.Mutex
	retention time.Duration
	buckets   map[int64]map[string]*entry // keyed by bucket index
}

type entry struct {
	count    int
	lastSeen time.Time
}

type DomainCount struct {
	Domain   string
	Count    int
	LastSeen time.Time
}

func New(retention time.Duration) *Blocked {
	return &Blocked{
		retention: retention,
		buckets:   map[int64]map[string]*entry{},
	}
}

func bucket(t time.Time) int64 {
	return t.Unix() / int64(bucketSize/time.Second)
}

func (b *Blocked) Record(domain string, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()

	key := bucket(now)
	current, ok := b.buckets[key]
	if !ok {
		current = map[string]*entry{}
		b.buckets[key] = current

		// New bucket, so drop anything past the retention period
		oldest := bucket(now.Add(-b.retention))
		for k := range b.buckets {
			if k < oldest {
				delete(b.buckets, k)
			}
		}
	}

	e, ok := current[domain]
	if !ok {
		e = &entry{}
		current[domain] = e
	}
	e.count++
	e.lastSeen = now
}

// Recent returns domains blocked within the window, most recently seen first.
func (b *Blocked) Recent(now time.Time, window time.Duration, limit int) []DomainCount {
	res := b.aggregate(now, window)
	sort.Slice(res, func(i, j int) bool {
		return res[i].LastSeen.After(res[j].LastSeen)
	})
	return truncate(res, limit)
}

// Top returns domains blocked within the window, most blocked first.
func (b *Blocked) Top(now time.Time, window time.Duration, limit int) []DomainCount {
	res := b.aggregate(now, window)
	sort.Slice(res, func(i, j int) bool {
		if res[i].Count != res[j].Count {
			return res[i].Count > res[j].Count
		}
		return res[i].Domain < res[j].Domain
	})
	return truncate(res, limit)
}

func (b *Blocked) aggregate(now time.Time, window time.Duration) []DomainCount {
	b.mu.Lock()
	defer b.mu.Unlock()

	from := bucket(now.Add(-window))
	totals := map[string]*DomainCount{}
	for key, entries := range b.buckets {
		if key < from {
			continue
		}
		for domain, e := range entries {
			t, ok := totals[domain]
			if !ok {
				t = &DomainCount{Domain: domain}
				totals[domain] = t
			}
			t.Count += e.count
			if e.lastSeen.After(t.LastSeen) {
				t.LastSeen = e.lastSeen
			}
		}
	}

	res := make([]DomainCount, 0, len(totals))
	for _, t := range totals {
		res = append(res, *t)
	}
	return res
}

func truncate(res []DomainCount, limit int) []DomainCount {
	if limit > 0 && len(res) > limit {
		return res[:limit]
	}
	return res
}
