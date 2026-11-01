package admin

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"dns-adblock/database"
	"dns-adblock/stats"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setup(t *testing.T) (*database.Database, http.Handler) {
	t.Chdir(t.TempDir())
	config := `{"blockLists": [], "whitelist": ["a.com"], "hostsFile": {}, "adminAddr": "127.0.0.1:0"}`
	require.NoError(t, os.WriteFile("dns-adblock.json", []byte(config), 0644))

	db := database.Start(time.Minute)
	require.NoError(t, db.LoadConfig())
	db.Blocked = stats.New(30 * 24 * time.Hour)
	db.Blocked.Record("ads.example.com", time.Now())

	s := &server{db: db}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.index)
	mux.HandleFunc("POST /whitelist", s.whitelist)
	return db, localOnly(mux)
}

func TestIndex(t *testing.T) {
	_, h := setup(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.7.0.2:5000"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "ads.example.com")
	assert.Contains(t, rec.Body.String(), "Latest blocked")
	assert.Contains(t, rec.Body.String(), "<details>")
}

func TestPublicIPRejected(t *testing.T) {
	_, h := setup(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "8.8.8.8:5000"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestCrossOriginPostRejected(t *testing.T) {
	db, h := setup(t)

	req := httptest.NewRequest(http.MethodPost, "/whitelist", strings.NewReader("domain=ads.example.com"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://evil.com")
	req.RemoteAddr = "127.0.0.1:5000"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.False(t, db.IsWhitelisted("ads.example.com"))
}

func TestWhitelist(t *testing.T) {
	db, h := setup(t)

	form := url.Values{"domain": {"ads.example.com"}}
	req := httptest.NewRequest(http.MethodPost, "/whitelist", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "127.0.0.1:5000"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.True(t, db.IsWhitelisted("ads.example.com"))

	saved, err := os.ReadFile("dns-adblock.json")
	require.NoError(t, err)
	assert.Contains(t, string(saved), `"a.com",`)
	assert.Contains(t, string(saved), `"ads.example.com"`)
	assert.Contains(t, string(saved), `"adminAddr": "127.0.0.1:0"`)
}
