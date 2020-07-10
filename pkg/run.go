package pkg

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	hosts "github.com/tomoyamachi/go-dnsmasq/pkg/hostsfile"
	"github.com/tomoyamachi/go-dnsmasq/pkg/log"
	"github.com/tomoyamachi/go-dnsmasq/pkg/resolvconf"
	"github.com/tomoyamachi/go-dnsmasq/pkg/server"
	"github.com/tomoyamachi/go-dnsmasq/pkg/stats"
)

type Args struct {
	NameServers []string
}

func Run(sconf *server.Config, version string) error {
	exitReason := make(chan error)
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
		sig := <-c
		log.Info("Application exit requested by signal:", sig)
		exitReason <- nil
	}()

	// if c.Bool("multithreading") {
	// 	runtime.GOMAXPROCS(runtime.NumCPU() + 1)
	// }

	if err := server.CheckConfig(sconf); err != nil {
		return fmt.Errorf("check server config: %w", err)
	}

	log.Infof("Nameservers: %v", sconf.Nameservers)
	if sconf.EnableSearch {
		log.Infof("Search domains: %v", sconf.SearchDomains)
	}

	hf, err := hosts.NewHostsfile(sconf.Hostsfile, &hosts.Config{
		Poll:    sconf.PollInterval,
		Verbose: sconf.Verbose,
	})
	if err != nil {
		return fmt.Errorf("loading hostsfile: %w", err)
	}

	s := server.New(hf, sconf, version)

	defer s.Stop()

	stats.Collect()

	if sconf.DefaultResolver {
		address, _, _ := net.SplitHostPort(sconf.DnsAddr)
		if err := resolvconf.StoreAddress(address); err != nil {
			return fmt.Errorf("register as default nameserver: %w", err)
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

	err = <-exitReason
	return err
}
