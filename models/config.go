package models

type Config struct {
	Blocklists       []Sources
	WhitelistDomains map[string]interface{}
	Hosts            map[string]string
	// AdminAddr is the listen address for the admin page, e.g. "10.0.0.1:8080".
	// Empty disables the admin page.
	AdminAddr string
}

type Sources struct {
	Regex string `json:"regex"`
	Url   string `json:"url"`
}
