package pkg

import (
	"context"
	"errors"
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

	"golang.org/x/sync/errgroup"
)

type Args struct {
	NameServers []string
}

func Run(sconf *server.Config, version string) error {
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
	log.Debug("create server")
	s := server.New(hf, sconf, version)
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
