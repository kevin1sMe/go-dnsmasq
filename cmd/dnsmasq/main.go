// Copyright (c) 2015 Jan Broer. All rights reserved.
// Use of this source code is governed by The MIT License (MIT) that can be
// found in the LICENSE file.

package main

import (
	"fmt"
	nativelog "log"
	"os"
	"time"

	"github.com/urfave/cli"

	"github.com/tomoyamachi/go-dnsmasq/pkg"
	"github.com/tomoyamachi/go-dnsmasq/pkg/log"
	"github.com/tomoyamachi/go-dnsmasq/pkg/resolvconf"
	"github.com/tomoyamachi/go-dnsmasq/pkg/server"
	"github.com/tomoyamachi/go-dnsmasq/pkg/types"
)

// set at build time
var Version = "dev"

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
		log.Infof("Starting go-dnsmasq server %s", Version)

		nameservers, err := server.CreateNameservers(c.StringSlice("nameservers"))
		if err != nil {
			return err
		}

		searchDomains, err := server.CreateSearchDomains(c.StringSlice("search-domains"))
		if err != nil {
			return err
		}

		stubmap, err := server.CreateStubMap(c.StringSlice("stubzones"))
		if err != nil {
			return err
		}

		listen, err := server.CreateListenAddress(c.String("listen"))
		if err != nil {
			return err
		}

		config := &server.Config{
			DnsAddr:         listen,
			DefaultResolver: c.Bool("default-resolver"),
			Nameservers:     nameservers,
			Systemd:         c.Bool("systemd"),
			SearchDomains:   searchDomains,
			EnableSearch:    c.Bool("enable-search"),
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
		if err := server.ResolvConf(config, c.IsSet("ndots")); err != nil {
			if !os.IsNotExist(err) {
				return fmt.Errorf("parsing resolve.conf: %w", err)
			}
		}

		s, err := pkg.BuildServer(config, nil, Version)
		if err != nil {
			return err
		}
		return pkg.Run(s)
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
