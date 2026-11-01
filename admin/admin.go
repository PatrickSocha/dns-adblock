package admin

import (
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"dns-adblock/database"
	"dns-adblock/stats"
)

const (
	latestLimit  = 10
	recentWindow = time.Hour
	recentLimit  = 500
	topWindow    = 30 * 24 * time.Hour
	topLimit     = 100
)

var page = template.Must(template.New("admin").Parse(`<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DNS Adblock</title>
<style>
body { font-family: sans-serif; margin: 8px; }
table { border-collapse: collapse; width: 100%; max-width: 900px; }
th, td { border: 1px solid #999; padding: 4px 6px; text-align: left; }
td:first-child { word-break: break-all; }
td.n { white-space: nowrap; }
form { margin: 0; }
summary { cursor: pointer; }
summary h2 { display: inline; }
details { margin: 1em 0; }
</style>
</head>
<body>
<h1>DNS Adblock</h1>
<form method="get" action="./"><button>Refresh</button></form>

{{define "whitelist"}}<td class="n">{{if .Whitelisted}}whitelisted{{else}}<form method="post" action="whitelist" onsubmit="return confirm('Whitelist ' + {{.Domain}} + '?')"><input type="hidden" name="domain" value="{{.Domain}}"><button>Whitelist</button></form>{{end}}</td>{{end}}
<h2>Latest blocked</h2>
<table>
<tr><th>Domain</th><th>#</th><th>Last</th><th></th></tr>
{{range .Latest}}
<tr>
<td>{{.Domain}}</td><td class="n">{{.Count}}</td><td class="n">{{.LastSeen.Format "Jan 2 15:04:05"}}</td>
{{template "whitelist" .}}
</tr>
{{else}}
<tr><td colspan="4">Nothing blocked</td></tr>
{{end}}
</table>

<details>
<summary><h2>Recently blocked (last hour)</h2></summary>
<table>
<tr><th>Domain</th><th>#</th><th>Last</th><th></th></tr>
{{range .Recent}}
<tr>
<td>{{.Domain}}</td><td class="n">{{.Count}}</td><td class="n">{{.LastSeen.Format "15:04"}}</td>
{{template "whitelist" .}}
</tr>
{{else}}
<tr><td colspan="4">Nothing blocked</td></tr>
{{end}}
</table>
</details>

<details>
<summary><h2>Most blocked (30d)</h2></summary>
<table>
<tr><th>Domain</th><th>#</th><th>Last</th></tr>
{{range .Top}}
<tr><td>{{.Domain}}</td><td class="n">{{.Count}}</td><td class="n">{{.LastSeen.Format "Jan 2"}}</td></tr>
{{else}}
<tr><td colspan="3">Nothing blocked</td></tr>
{{end}}
</table>
</details>

<p>Stats are held in memory and reset when the server restarts.</p>
</body>
</html>
`))

type row struct {
	stats.DomainCount
	Whitelisted bool
}

type server struct {
	db *database.Database
}

// Start serves the admin page on addr in the background. Requests from
// non-private IPs are rejected, so bind it to a local or VPN address.
func Start(addr string, db *database.Database) {
	s := &server{db: db}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.index)
	mux.HandleFunc("POST /whitelist", s.whitelist)

	go func() {
		log.Printf("Starting admin page at http://%s\n", addr)
		if err := http.ListenAndServe(addr, localOnly(mux)); err != nil {
			log.Printf("error starting admin page: %v", err)
		}
	}()
}

func localOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		ip := net.ParseIP(host)
		if err != nil || ip == nil || !(ip.IsPrivate() || ip.IsLoopback()) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		// Stop other websites submitting forms to the admin page
		if r.Method == http.MethodPost {
			if origin := r.Header.Get("Origin"); origin != "" {
				u, err := url.Parse(origin)
				if err != nil || u.Host != r.Host {
					http.Error(w, "forbidden", http.StatusForbidden)
					return
				}
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (s *server) index(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	data := struct {
		Latest []row
		Recent []row
		Top    []stats.DomainCount
	}{}

	if s.db.Blocked != nil {
		data.Latest = s.rows(s.db.Blocked.Recent(now, topWindow, latestLimit))
		data.Recent = s.rows(s.db.Blocked.Recent(now, recentWindow, recentLimit))
		data.Top = s.db.Blocked.Top(now, topWindow, topLimit)
	}

	if err := page.Execute(w, data); err != nil {
		log.Printf("error rendering admin page: %v", err)
	}
}

func (s *server) rows(counts []stats.DomainCount) []row {
	res := make([]row, 0, len(counts))
	for _, d := range counts {
		res = append(res, row{DomainCount: d, Whitelisted: s.db.IsWhitelisted(d.Domain)})
	}
	return res
}

func (s *server) whitelist(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimSpace(r.FormValue("domain"))
	if domain == "" || strings.ContainsAny(domain, " /\t\r\n") {
		http.Error(w, "invalid domain", http.StatusBadRequest)
		return
	}

	if err := s.db.AddWhitelist(domain); err != nil {
		log.Printf("error whitelisting %s: %v", domain, err)
		http.Error(w, "error whitelisting domain: "+err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "./", http.StatusSeeOther)
}
