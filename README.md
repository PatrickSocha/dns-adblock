# DNS Adblock

DumbDNS is a stupid simple DNS proxy with Ad Blocking written in [Go](https://go.dev/). It compiles to a single Go binary and is exceptionally easy to run. It's not designed to be feature rich or complete.

Life's too short to be setting up PiHole and maintaining it. You can start using DumbDNS with a few easy commands.

DumbDNS currently comes with the following features:

- Ad blocking
- Cached lookups (5 min TTL)
- Block list refreshing (every 2 hours)
- White list (bypass any blocked domain)
- Fetches DNS over HTTPS, serves as DNS*
- Rejects external IPs
- Misses out 99% of the DNS spec (:
- Supports the following query types:
  - A
  - AAAA
  - CNAME
  - NS
  - MX (priority set to 10)
- Limited testing, with aim to add a lot more.

### Use cases

I've been running a WireGuard server with DumbDNS on both my laptop and phone for a few years now and it works great.

*DumbDNS queries the authority servers via DNS over HTTPS (DoH) and I have configured my WireGuard clients to query DumbDNS via the local WireGuard network. Therefore, the DNS response is tunneled and secure.

### Getting started (Ubuntu)

Build the Go binary for Linux

```bash
GOOS=linux GOARCH=amd64 go build
```

Stop the system DNS service and free up port 53

```bash
service systemd-resolved stop
```

Set the system default DNS to 1.1.1.1 (CloudFlare) or 8.8.8.8 (Google) so we can download the blocklists.

```bash
nano /etc/resolv.conf
nameserver 8.8.8.8
```

Start the service in the background
```bash
./dumbdns &
```

**Note**: External non-private IPs are rejected and the service will bind to port 53.

### Create your blocklist

The blocklist has three distinct parts:

- **Block List**: This requires the Go Regex to read the file and return a capture group.
- **White List**: These are individual URLs you would like to allow the server to allow and ignore if found in the blocklist.
- **Hosts File**: This allows you to create a custom mapping of domain to ip. In the given example, archive.is blocks CloudFlare DNS, so we manually add the mapping to make it work.

You should save this as `dumbdns.json` in the same folder as the executable binary.

```json
{
  "blockLists":[
    {
      "regex": "0.0.0.0\\s+(?P<url>\\S+)",
      "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
    }
  ],
  "whitelist": [
    "spclient.wg.spotify.com",
    "api-partner.spotify.com",
    "i.scdn.co",
    "encore.scdn.co",
    "cdn.jsdelivr.net",
    "cdnjs.com",
    "unpkg.com",
    "cdnjs.cloudflare.com",
    "downloaddispatch.itunes.apple.com",
    "xp.apple.com",
    "gsa.apple.com",
    "init.push.apple.com"
  ],
  "hostsFile": {
    "archive.is": "23.137.248.133"
  }
}
```

### Project Roadmap

- ~~Config file~~
- ~~IPv6 support~~
- ~~DNS over HTTPS (DoH)~~
- A simple way to add domains to the whitelist
- Testing of critical components

### Who built this & licenses.

This DNS Proxy is created by [Patrick Socha](https://psocha.co.uk) and is licensed under the [MIT License](LICENSE).

It makes use of the [miekg/dns](https://github.com/miekg/dns) package, which is licensed under [BSD 3-Clause "New" or "Revised" License](https://github.com/miekg/dns/blob/master/LICENSE).
