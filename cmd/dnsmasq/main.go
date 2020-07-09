// Copyright (c) 2015 Jan Broer. All rights reserved.
// Use of this source code is governed by The MIT License (MIT) that can be
// found in the LICENSE file.

package main

import (
	"fmt"
	nativelog "log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/urfave/cli"

	"github.com/tomoyamachi/go-dnsmasq/pkg/hostsfile"
	"github.com/tomoyamachi/go-dnsmasq/pkg/log"
	"github.com/tomoyamachi/go-dnsmasq/pkg/resolvconf"
	"github.com/tomoyamachi/go-dnsmasq/pkg/server"
	"github.com/tomoyamachi/go-dnsmasq/pkg/stats"
	"github.com/tomoyamachi/go-dnsmasq/pkg/types"
)

// set at build time
var Version = "dev"
var exitErr error

func main() {
	app := cli.NewApp()
	app.Name = "go-dnsmasq"
	app.Usage = "Lightweight caching DNS server and forwarder\n   Website: http://github.com/tomoyamachi/go-dnsmasq"
	app.UsageText = "go-dnsmasq [global options]"
	app.Version = Version
	app.Author, app.Email = "", ""
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "log-level",
			Value:  "info",
			Usage:  "log level",
			EnvVar: types.LogLevel, // deprecated DNSMASQ_SEARCH
		},
		cli.StringFlag{
			Name:   "listen, l",
			Value:  "127.0.0.1:53",
			Usage:  "Listen on this `address` <host[:port]>",
			EnvVar: types.Listen,
		},
		cli.BoolFlag{
			Name:   "default-resolver, d",
			Usage:  "Update /etc/resolv.conf with the address of go-dnsmasq as nameserver",
			EnvVar: types.DefaultResolver,
		},
		cli.StringSliceFlag{
			Name:   "nameservers, n",
			Usage:  "Comma delimited list of `nameservers` <host[:port][,host[:port]]> (supersedes resolv.conf)",
			EnvVar: types.NameServers,
		},
		cli.StringSliceFlag{
			Name:   "stubzones, z",
			Usage:  "Use different nameservers for given domains <domain[,domain]/host[:port][,host[:port]]>",
			EnvVar: types.StubZone,
		},
		cli.StringFlag{
			Name:   "hostsfile, f",
			Usage:  "Path to a hosts `file` (e.g. /etc/hosts)",
			EnvVar: types.HostsFile,
		},
		cli.DurationFlag{
			Name:   "hostsfile-poll, p",
			Value:  0,
			Usage:  "How frequently to poll hosts file (`1s`, '0' to disable)",
			EnvVar: types.HostsFilePollDuration,
		},
		cli.StringSliceFlag{
			Name:   "search-domains, s",
			Usage:  "List of search domains <domain[,domain]> (supersedes resolv.conf)",
			EnvVar: types.SearchDomains,
		},
		cli.BoolFlag{
			Name:   "enable-search, search",
			Usage:  "Qualify names with search domains to resolve queries",
			EnvVar: types.EnableSearch,
		},
		cli.IntFlag{
			Name:   "rcache, r",
			Value:  0,
			Usage:  "Response cache `capacity` ('0' disables caching)",
			EnvVar: types.ResponseCacheCap,
		},
		cli.DurationFlag{
			Name:   "rcache-ttl",
			Value:  time.Minute,
			Usage:  "TTL for response cache entries",
			EnvVar: types.ResponseCacheTTL,
		},
		cli.BoolFlag{
			Name:   "no-rec",
			Usage:  "Disable recursion",
			EnvVar: types.DisableRecursion,
		},
		cli.IntFlag{
			Name:   "fwd-ndots",
			Usage:  "Number of `dots` a name must have before the query is forwarded",
			EnvVar: types.FwdNdots,
		},
		cli.IntFlag{
			Name:   "ndots",
			Value:  1,
			Usage:  "Number of `dots` a name must have before doing an initial absolute query (supersedes resolv.conf)",
			EnvVar: types.Ndots,
		},
		cli.BoolFlag{
			Name:   "round-robin",
			Usage:  "Enable round robin of A/AAAA records",
			EnvVar: types.RoundRobin,
		},
		cli.BoolFlag{
			Name:   "systemd",
			Usage:  "Bind to socket activated by Systemd (supersedes '--listen')",
			EnvVar: types.Systemd,
		},
	}

	app.Action = func(c *cli.Context) error {
		if err := log.New(c.String("log-level")); err != nil {
			nativelog.Fatal(err)
		}
		exitReason := make(chan error)
		go func() {
			c := make(chan os.Signal, 1)
			signal.Notify(c, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
			sig := <-c
			log.Info("Application exit requested by signal:", sig)
			exitReason <- nil
		}()
		enableSearch := c.Bool("enable-search")

		// if c.Bool("multithreading") {
		// 	runtime.GOMAXPROCS(runtime.NumCPU() + 1)
		// }

		nameservers, err := createNameservers(c.StringSlice("nameservers"))
		if err != nil {
			log.Fatal(err)
		}

		searchDomains, err := createSearchDomains(c.StringSlice("search-domains"))
		if err != nil {
			log.Fatal(err)
		}

		stubmap, err := createStubMap(c.StringSlice("stubzones"))
		if err != nil {
			log.Fatal(err)
		}

		listen, err := createListenAddress(c.String("listen"))
		if err != nil {
			log.Fatal(err)
		}

		config := &server.Config{
			DnsAddr:         listen,
			DefaultResolver: c.Bool("default-resolver"),
			Nameservers:     nameservers,
			Systemd:         c.Bool("systemd"),
			SearchDomains:   searchDomains,
			EnableSearch:    enableSearch,
			Hostsfile:       c.String("hostsfile"),
			PollInterval:    c.Duration("hostsfile-poll"),
			RoundRobin:      c.Bool("round-robin"),
			NoRec:           c.Bool("no-rec"),
			FwdNdots:        c.Int("fwd-ndots"),
			Ndots:           c.Int("ndots"),
			ReadTimeout:     2 * time.Second,
			RCache:          c.Int("rcache"),
			RCacheTtl:       c.Duration("rcache-ttl"),
			Verbose:         c.Bool("verbose"),
			Stub:            stubmap,
		}

		resolvconf.Clean()
		if err := server.ResolvConf(config, c); err != nil {
			if !os.IsNotExist(err) {
				log.Errorf("Error parsing resolv.conf: %s", err.Error())
			}
		}

		if err := server.CheckConfig(config); err != nil {
			log.Fatal(err.Error())
		}

		log.Infof("Starting go-dnsmasq server %s", Version)
		log.Infof("Nameservers: %v", config.Nameservers)
		if config.EnableSearch {
			log.Infof("Search domains: %v", config.SearchDomains)
		}

		hf, err := hosts.NewHostsfile(config.Hostsfile, &hosts.Config{
			Poll:    config.PollInterval,
			Verbose: config.Verbose,
		})
		if err != nil {
			log.Fatalf("Error loading hostsfile: %s", err)
		}

		s := server.New(hf, config, Version)

		defer s.Stop()

		stats.Collect()

		if config.DefaultResolver {
			address, _, _ := net.SplitHostPort(config.DnsAddr)
			err := resolvconf.StoreAddress(address)
			if err != nil {
				log.Errorf("Failed to register as default nameserver: %s", err)
			}

			defer func() {
				log.Info("Restoring /etc/resolv.conf")
				resolvconf.Clean()
			}()
		}

		go func() {
			if err := s.Run(); err != nil {
				exitReason <- err
			}
		}()

		exitErr = <-exitReason
		if exitErr != nil {
			log.Fatalf("Server error: %s", err)
		}

		return nil
	}

	app.Run(os.Args)
}

func createListenAddress(listen string) (string, error) {
	if strings.HasSuffix(listen, "]") {
		listen += ":53"
	} else if !strings.Contains(listen, ":") {
		listen += ":53"
	}
	if err := validateHostPort(listen); err != nil {
		return "", fmt.Errorf("Listen address: %s", err)
	}
	return listen, nil
}

func createSearchDomains(domains []string) ([]string, error) {
	searchDomains := []string{}
	for _, domain := range domains {
		if dns.CountLabel(domain) < 2 {
			return nil, fmt.Errorf("Search domain must have at least one dot in name: %s", domain)
		}
		domain = strings.TrimSpace(domain)
		domain = dns.Fqdn(strings.ToLower(domain))
		searchDomains = append(searchDomains, domain)
	}
	return searchDomains, nil
}

func createNameservers(servers []string) ([]string, error) {
	nameservers := []string{}
	for _, hostPort := range servers {
		hostPort = strings.TrimSpace(hostPort)
		if strings.HasSuffix(hostPort, "]") {
			hostPort += ":53"
		} else if !strings.Contains(hostPort, ":") {
			hostPort += ":53"
		}
		if err := validateHostPort(hostPort); err != nil {
			return nil, fmt.Errorf("Nameserver is invalid: %s", err)
		}
		nameservers = append(nameservers, hostPort)
	}
	return nameservers, nil
}

func createStubMap(stubzones []string) (map[string][]string, error) {
	if len(stubzones) == 0 {
		return nil, nil
	}
	stubmap := make(map[string][]string)
	for _, stubzone := range stubzones {
		segments := strings.Split(stubzone, "/")
		if len(segments) != 2 || len(segments[0]) == 0 || len(segments[1]) == 0 {
			return nil, fmt.Errorf("Invalid value for --stubzones")
		}

		hosts := strings.Split(segments[1], ",")
		for _, hostPort := range hosts {
			hostPort = strings.TrimSpace(hostPort)
			if strings.HasSuffix(hostPort, "]") {
				hostPort += ":53"
			} else if !strings.Contains(hostPort, ":") {
				hostPort += ":53"
			}

			if err := validateHostPort(hostPort); err != nil {
				return nil, fmt.Errorf("Stubzone server address is invalid: %s", err)
			}

			for _, sdomain := range strings.Split(segments[0], ",") {
				if dns.CountLabel(sdomain) < 1 {
					return nil, fmt.Errorf("Stubzone domain is not a fully-qualified domain name: %s", sdomain)
				}
				sdomain = strings.TrimSpace(sdomain)
				sdomain = dns.Fqdn(sdomain)
				stubmap[sdomain] = append(stubmap[sdomain], hostPort)
			}
		}
	}

	return stubmap, nil
}

func validateHostPort(hostPort string) error {
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); ip == nil {
		return fmt.Errorf("Bad IP address: %s", host)
	}

	if p, _ := strconv.Atoi(port); p < 1 || p > 65535 {
		return fmt.Errorf("Bad port number %s", port)
	}
	return nil
}
