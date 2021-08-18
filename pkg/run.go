package pkg

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	hosts "github.com/soulteary/go-dnsmasq/pkg/hostsfile"
	"github.com/soulteary/go-dnsmasq/pkg/log"
	"github.com/soulteary/go-dnsmasq/pkg/resolvconf"
	"github.com/soulteary/go-dnsmasq/pkg/server"
	"github.com/soulteary/go-dnsmasq/pkg/stats"

	"golang.org/x/sync/errgroup"
)

type Args struct {
	NameServers []string
}

func BuildServer(sconf *server.Config, f *server.PluggableFunc, version string) (s *server.Server, err error) {
	if err := server.CheckConfig(sconf); err != nil {
		return nil, fmt.Errorf("check server config: %w", err)
	}

	log.Infof("Nameservers: %v", sconf.Nameservers)
	if sconf.EnableSearch {
		log.Infof("Search domains: %v", sconf.SearchDomains)
	}

	var hf *hosts.Hostsfile
	var hfs *hosts.Hostsfiles
	hostfileConfig := &hosts.Config{
		Poll:    sconf.PollInterval,
		Verbose: sconf.Verbose,
	}
	
	if sconf.DirectoryHostsfiles != "" {
		if hfs, err = hosts.NewHostsfiles(sconf.DirectoryHostsfiles, hostfileConfig); err != nil {
			return nil, fmt.Errorf("loading hostsfile: %w", err)
		}
	} else {
		if hf, err = hosts.NewHostsfile(sconf.Hostsfile, hostfileConfig); err != nil {
			return nil, fmt.Errorf("loading hostsfile: %w", err)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("loading hostsfile: %w", err)
	}

	if sconf.DefaultResolver {
		address, _, err := net.SplitHostPort(sconf.DnsAddr)
		if err != nil {
			return nil, fmt.Errorf("SplitHostPort from resolver : %w", err)
		}
		if err := resolvconf.StoreAddress(address); err != nil {
			return nil, fmt.Errorf("register as default nameserver: %w", err)
		}
	}

	if sconf.DirectoryHostsfiles != "" {
		log.Debug("create server")
		return server.New(hfs, sconf, version, f), nil
	} else {
		log.Debug("create server")
		return server.New(hf, sconf, version, f), nil
	}

}

func Run(s *server.Server) error {
	defer func() {
		log.Info("Restoring /etc/resolv.conf")
		resolvconf.Clean()
	}()

	// trap Ctrl+C and call cancel on the context
	ctx, done := context.WithCancel(context.Background())
	eg, gctx := errgroup.WithContext(ctx)

	// Check Ctrl+C or Signals
	eg.Go(func() error {
		signalChannel := make(chan os.Signal, 1)
		signal.Notify(signalChannel, os.Interrupt, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

		select {
		case sig := <-signalChannel:
			log.Debugf("Received signal: %s\n", sig)
			done()
		case <-gctx.Done():
			log.Debugf("closing signal goroutine\n")
			return gctx.Err()
		}

		return nil
	})

	stats.Collect()

	// Run DNS server
	eg.Go(func() error {
		errCh := make(chan error)
		go func() { errCh <- s.Run(gctx) }()
		select {
		case err := <-errCh:
			log.Debug("error from errCh", err)
			return err
		case <-gctx.Done():
			return gctx.Err()
		}
	})

	if err := eg.Wait(); err != nil {
		if errors.Is(err, context.Canceled) {
			log.Info("context was canceled")
			return nil
		} else {
			log.Error("error", err)
			return err
		}
	}
	return nil
}
