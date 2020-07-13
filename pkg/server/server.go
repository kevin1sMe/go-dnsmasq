// Copyright (c) 2015 Jan Broer. All rights reserved.
// Contains code (c) 2014 The SkyDNS Authors
// Use of this source code is governed by The MIT License (MIT) that can be
// found in the LICENSE file.

package server

import (
	"context"
	"fmt"
	"net"

	"github.com/coreos/go-systemd/activation"
	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"

	"github.com/tomoyamachi/go-dnsmasq/pkg/cache"
	"github.com/tomoyamachi/go-dnsmasq/pkg/log"
)

type PluggableFunc func(m *dns.Msg, q dns.Question, targetName string, isTCP bool) (*dns.Msg, error)
type Server struct {
	hosts   Hostfile
	config  *Config
	version string

	pluggableFunc *PluggableFunc

	dnsUDPclient *dns.Client // used for forwarding queries
	dnsTCPclient *dns.Client // used for forwarding queries
	rcache       *cache.Cache
}

type Hostfile interface {
	FindHosts(name string) ([]net.IP, error)
	FindReverse(name string) (string, error)
}

// New returns a new Server.
func New(hostfile Hostfile, config *Config, v string, f *PluggableFunc) *Server {
	return &Server{
		hosts:         hostfile,
		config:        config,
		version:       v,
		rcache:        cache.New(config.RCache, config.RCacheTtl),
		dnsUDPclient:  &dns.Client{Net: "udp", ReadTimeout: 2 * config.ReadTimeout, WriteTimeout: 2 * config.ReadTimeout, SingleInflight: true},
		dnsTCPclient:  &dns.Client{Net: "tcp", ReadTimeout: 2 * config.ReadTimeout, WriteTimeout: 2 * config.ReadTimeout, SingleInflight: true},
		pluggableFunc: f,
	}
}

// Run is a blocking operation that starts the Server listening on the DNS ports.
func (s *Server) Run(ctx context.Context) error {
	mux := dns.NewServeMux()
	mux.Handle(".", s)
	if s.config.Systemd {
		return s.runSystemd(ctx, mux)
	}
	log.Debug("start as proccess")
	return s.runProccess(ctx, mux)
}

func (s *Server) runProccess(ctx context.Context, mux *dns.ServeMux) error {
	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(s.dnsListenAndServerWithContext(ctx, s.config.DnsAddr, "tcp", mux))
	s.dnsReadyMsg(s.config.DnsAddr, "tcp")
	eg.Go(s.dnsListenAndServerWithContext(ctx, s.config.DnsAddr, "udp", mux))
	s.dnsReadyMsg(s.config.DnsAddr, "udp")
	return eg.Wait()
}

func (s *Server) dnsListenAndServerWithContext(ctx context.Context, addr, net string, mux *dns.ServeMux) func() error {
	return func() error {
		server := &dns.Server{Addr: addr, Net: net, Handler: mux}
		go func() {
			select {
			case <-ctx.Done():
				server.ShutdownContext(ctx)
			}
		}()
		if err := server.ListenAndServe(); err != nil {
			return fmt.Errorf("%s %s : %w", net, addr, err)
		}
		return nil
	}
}

func (s *Server) runSystemd(ctx context.Context, mux *dns.ServeMux) error {
	packetConns, err := activation.PacketConns()
	if err != nil {
		return err
	}
	listeners, err := activation.Listeners()
	if err != nil {
		return err
	}
	if len(packetConns) == 0 && len(listeners) == 0 {
		return fmt.Errorf("No UDP or TCP sockets supplied by systemd")
	}
	eg, ctx := errgroup.WithContext(ctx)
	for _, p := range packetConns {
		if u, ok := p.(*net.UDPConn); ok {
			u := u
			eg.Go(s.dnsActivateAndServeWithContext(ctx, nil, u, mux))
			s.dnsReadyMsg(u.LocalAddr().String(), "udp")
		}
	}
	for _, l := range listeners {
		if t, ok := l.(*net.TCPListener); ok {
			t := t
			eg.Go(s.dnsActivateAndServeWithContext(ctx, t, nil, mux))
			s.dnsReadyMsg(t.Addr().String(), "tcp")
		}
	}
	return eg.Wait()
}

func (s *Server) dnsActivateAndServeWithContext(ctx context.Context, l net.Listener, p net.PacketConn, mux *dns.ServeMux) func() error {
	return func() error {
		server := &dns.Server{Listener: l, PacketConn: p, Handler: mux}
		go func() {
			select {
			case <-ctx.Done():
				server.ShutdownContext(ctx)
			}
		}()
		if err := server.ActivateAndServe(); err != nil {
			if l != nil {
				return fmt.Errorf("tcp %s : %w", l.Addr().String(), err)
			}
			if p != nil {
				return fmt.Errorf("udp %s : %w", p.LocalAddr().String(), err)
			}
			return fmt.Errorf("ActivateAndServe: %w", err)
		}
		return nil
	}
}

func (s *Server) dnsReadyMsg(addr, net string) {
	rCacheState := "disabled"
	if s.config.RCache > 0 {
		rCacheState = fmt.Sprintf("capacity: %d", s.config.RCache)
	}
	log.Infof("Ready for queries on %s://%s [cache: %s]", net, addr, rCacheState)
}

// isTCP returns true if the client is connecting over TCP.
func isTCP(w dns.ResponseWriter) bool {
	_, ok := w.RemoteAddr().(*net.TCPAddr)
	return ok
}
