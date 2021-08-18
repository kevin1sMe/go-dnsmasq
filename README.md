# go-dnsmasq

this is a fork of [janeczku/go-dnsmasq](https://github.com/janeczku/go-dnsmasq) and [Doout/go-dnsmasq](https://github.com/Doout/go-dnsmasq).

go-dnsmasq is a lightweight DNS caching server/forwarder with minimal filesystem and runtime overhead.

## Dynamic Name resolving

go-dnsmasq provides pluggable DNS resolve function.

```go
package main

import (
	"math/rand"
	"net"
	"os"
	"time"

	"github.com/miekg/dns"
	"github.com/soulteary/go-dnsmasq/pkg"
	"github.com/soulteary/go-dnsmasq/pkg/log"
	"github.com/soulteary/go-dnsmasq/pkg/resolvconf"
	"github.com/soulteary/go-dnsmasq/pkg/server"
)

// return 1.1.1.1 randomly
func return1111() server.PluggableFunc {
	return func(m *dns.Msg, q dns.Question, targetName string, isTCP bool) (*dns.Msg, error) {
		if rand.Intn(10) > 4 {
			return nil, nil
		}
		r := new(dns.A)
		r.Hdr = dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA,
			Class: dns.ClassINET, Ttl: 10}
		r.A = net.ParseIP("1.1.1.1")
		m.Answer = append(m.Answer, r)
		return m, nil
	}
}

func main() {
	log.New("debug")
	listen, err := server.CreateListenAddress("0.0.0.0:53")
	if err != nil {
		return
	}
	sconf := &server.Config{
		DnsAddr:         listen,
		DefaultResolver: true,
		Hostsfile:       "/etc/hosts",
		ReadTimeout:     time.Second,
	}
	resolvconf.Clean()
	if err := server.ResolvConf(sconf, true); err != nil {
		if !os.IsNotExist(err) {
			log.Errorf("parsing resolve.conf: %w", err)
			return
		}
	}
	pf := return1111()
	s, err := pkg.BuildServer(sconf, &pf, "")
	if err != nil {
		return
	}
	log.Error(pkg.Run(s))
}
```

### Application examples:

- Caching DNS server/forwarder in a local network
- Container/Host DNS cache
- DNS proxy providing DNS `search` capabilities to `musl-libc` based clients, particularly Alpine Linux

### Features

* Automatically set upstream `nameservers` and `search` domains from resolv.conf
* Insert itself into the host's /etc/resolv.conf on start
* Serve static A/AAAA records from a hosts file
* Provide DNS response caching
* Replicate the `search` domain treatment not supported by `musl-libc` based Linux distributions
* Supports virtually unlimited number of `search` paths and `nameservers` ([related Kubernetes article](https://github.com/kubernetes/kubernetes/tree/master/cluster/addons/dns#known-issues))
* Configure stubzones (different nameserver for specific domains)
* Round-robin of DNS records
* Send server metrics to Graphite and StatHat
* Configuration through both command line flags and environment variables

### Resolve logic

DNS queries are resolved in the style of the GNU libc resolver:
* The first nameserver (as listed in resolv.conf or configured by `--nameservers`) is always queried first, additional servers are considered fallbacks
* Multiple `search` domains are tried in the order they are configured. 
* Single-label queries (e.g.: "redis-service") are always qualified with the `search` domains
* Multi-label queries (ndots >= 1) are first tried as absolute names before qualifying them with the `search` domains

### Command-line options / environment variables

| Flag                           | Description                                                                   | Default       | Environment vars     |
| ------------------------------ | ----------------------------------------------------------------------------- | ------------- | -------------------- |
| --listen, -l                   | Address to listen on  `host[:port]`                                           | 127.0.0.1:53  | $DNSMASQ_LISTEN      |
| --default-resolver, -d         | Update resolv.conf to make go-dnsmasq the host's nameserver                   | False         | $DNSMASQ_DEFAULT     |
| --nameservers, -n              | Comma delimited list of nameservers `host[:port]`. IPv6 literal address must be enclosed in brackets. (supersedes etc/resolv.conf) | -  | $DNSMASQ_SERVERS     |
| --stubzones, -z                | Use different nameservers for given domains. Can be passed multiple times. `domain[,domain]/host[:port][,host[:port]]`   | -  |$DNSMASQ_STUB        |
| --hostsfile, -f                | Path to a hosts file (e.g. ‘/etc/hosts‘)                                      | -             | $DNSMASQ_HOSTSFILE   |
| --hostsfiles, --fs             | Path to a hosts file directory (e.g. ‘/etc/hosts‘)                            | -             | $DNSMASQ_DIRECTORY_HOSTSFILES   |
| --hostsfile-poll, -p           | How frequently to poll hosts file for changes (seconds, ‘0‘ to disable)       | 0             | $DNSMASQ_POLL        |
| --search-domains, -s           | Comma delimited list of search domains `domain[,domain]` (supersedes /etc/resolv.conf) | -             | $DNSMASQ_SEARCH_DOMAINS      |
| --enable-search, -search       | Qualify names with search domains to resolve queries                          | False         | $DNSMASQ_ENABLE_SEARCH      |
| --rcache, -r                   | Capacity of the response cache (‘0‘ disables caching)                         | 0             | $DNSMASQ_RCACHE      |
| --rcache-ttl                   | TTL for entries in the response cache                                         | 60            | $DNSMASQ_RCACHE_TTL  |
| --no-rec                       | Disable forwarding of queries to upstream nameservers                         | False         | $DNSMASQ_NOREC       |
| --fwd-ndots                    | Number of dots a name must have before the query is forwarded                 | 0 | $DNSMASQ_FWD_NDOTS   |
| --ndots                        | Number of dots a name must have before making an initial absolute query (supersedes /etc/resolv.conf) | 1  | $DNSMASQ_NDOTS |
| --round-robin                  | Enable round robin of A/AAAA records                                          | False         | $DNSMASQ_RR          |
| --verbose                      | Enable verbose logging                                                        | False         | $DNSMASQ_VERBOSE     |
| --help, -h                     | Show help                                                                     |               |                      |
| --version, -v                  | Print the version                                                             |               |                      |

#### Enable Graphite/StatHat metrics

EnvVar: **GRAPHITE_SERVER**  
Default: ` `  
Set to the `host:port` of the Graphite server

EnvVar: **GRAPHITE_PREFIX**  
Default: `go-dnsmasq`  
Set a custom prefix for Graphite metrics

EnvVar: **STATHAT_USER**  
Default: ` `  
Set to your StatHat account email address

### Usage

#### Run from the command line

Download the binary for your OS from the [releases page](https://github.com/soulteary/go-dnsmasq/releases/latest).    

go-dnsmasq is available in two versions. The minimal version (`go-dnsmasq-min`) has a lower memory footprint but doesn't have caching, stats reporting and systemd support.

```sh
   sudo ./go-dnsmasq [options]
```

#### Run as a Docker container

Docker Hub trusted builds are [available](https://hub.docker.com/r/soulteary/go-dnsmasq/).

```sh
docker run -d -p 53:53/udp -p 53:53 soulteary/go-dnsmasq
```

You can pass go-dnsmasq configuration parameters by setting the corresponding environmental variables with Docker's `-e` flag.

#### Serving A/AAAA records from a hosts file
The `--hostsfile` parameter expects a standard plain text [hosts file](https://en.wikipedia.org/wiki/Hosts_(file)) with the only difference being that a wildcard `*` in the left-most label of hostnames is allowed. Wildcard entries will match any subdomain that is not explicitly defined.
For example, given a hosts file with the following content:

```
192.168.0.1 db1.db.local
192.168.0.2 *.db.local
```

Queries for `db2.db.local` would be answered with an A record pointing to 192.168.0.2, while queries for `db1.db.local` would yield an A record pointing to 192.168.0.1.
