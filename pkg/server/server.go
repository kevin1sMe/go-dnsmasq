// Copyright (c) 2015 Jan Broer. All rights reserved.
// Contains code (c) 2014 The SkyDNS Authors
// Use of this source code is governed by The MIT License (MIT) that can be
// found in the LICENSE file.

package server

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/tomoyamachi/go-dnsmasq/pkg/cache"
	"github.com/tomoyamachi/go-dnsmasq/pkg/log"

	"github.com/coreos/go-systemd/activation"
	"github.com/miekg/dns"
)

type server struct {
	hosts   Hostfile
	config  *Config
	version string

	group        *sync.WaitGroup
	dnsUDPclient *dns.Client // used for forwarding queries
	dnsTCPclient *dns.Client // used for forwarding queries
	rcache       *cache.Cache
}

type Hostfile interface {
	FindHosts(name string) ([]net.IP, error)
	FindReverse(name string) (string, error)
}

// New returns a new server.
func New(hostfile Hostfile, config *Config, v string) *server {
	return &server{
		hosts:        hostfile,
		config:       config,
		version:      v,
		group:        new(sync.WaitGroup),
		rcache:       cache.New(config.RCache, config.RCacheTtl),
		dnsUDPclient: &dns.Client{Net: "udp", ReadTimeout: 2 * config.ReadTimeout, WriteTimeout: 2 * config.ReadTimeout, SingleInflight: true},
		dnsTCPclient: &dns.Client{Net: "tcp", ReadTimeout: 2 * config.ReadTimeout, WriteTimeout: 2 * config.ReadTimeout, SingleInflight: true},
	}
}

// Run is a blocking operation that starts the server listening on the DNS ports.
func (s *server) Run() error {
	mux := dns.NewServeMux()
	mux.Handle(".", s)

	dnsReadyMsg := func(addr, net string) {
		rCacheState := "disabled"
		if s.config.RCache > 0 {
			rCacheState = fmt.Sprintf("capacity: %d", s.config.RCache)
		}
		log.Infof("Ready for queries on %s://%s [cache: %s]", net, addr, rCacheState)
	}

	if s.config.Systemd {
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
		for _, p := range packetConns {
			if u, ok := p.(*net.UDPConn); ok {
				s.group.Add(1)
				go func() {
					defer s.group.Done()
					if err := dns.ActivateAndServe(nil, u, mux); err != nil {
						log.Fatalf("%s", err)
					}
				}()
				dnsReadyMsg(u.LocalAddr().String(), "udp")
			}
		}
		for _, l := range listeners {
			if t, ok := l.(*net.TCPListener); ok {
				s.group.Add(1)
				go func() {
					defer s.group.Done()
					if err := dns.ActivateAndServe(t, nil, mux); err != nil {
						log.Fatalf("%s", err)
					}
				}()
				dnsReadyMsg(t.Addr().String(), "tcp")
			}
		}
	} else {
		s.group.Add(1)
		go func() {
			defer s.group.Done()
			if err := dns.ListenAndServe(s.config.DnsAddr, "tcp", mux); err != nil {
				log.Fatalf("%s", err)
			}
		}()
		dnsReadyMsg(s.config.DnsAddr, "tcp")
		s.group.Add(1)
		go func() {
			defer s.group.Done()
			if err := dns.ListenAndServe(s.config.DnsAddr, "udp", mux); err != nil {
				log.Fatalf("%s", err)
			}
		}()
		dnsReadyMsg(s.config.DnsAddr, "udp")
	}

	s.group.Wait()
	return nil
}

// Stop stops a server.
func (s *server) Stop() {
	// TODO(miek)
	//s.group.Add(-2)
}

func (s *server) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	startTime := time.Now()
	defer func() {
		elapsed := time.Since(startTime)
		log.Debugf("[%d] Response time: %s", req.Id, elapsed)
	}()

	tcp, dnssec, bufsize, m, err := s.serveDNS(w, req)
	if err != nil {
		log.Errorf("Failed to return reply %q", err)
	}

	if m.Rcode == dns.RcodeServerFailure {
		if err := w.WriteMsg(m); err != nil {
			log.Errorf("Failed to return reply %q", err)
		}
		return
	}

	if tcp {
		if _, overflow := Fit(m, dns.MaxMsgSize, tcp); overflow {
			msgFail := new(dns.Msg)
			s.ServerFailure(msgFail, req)
			w.WriteMsg(msgFail)
			return
		}
	} else {
		Fit(m, int(bufsize), tcp)
	}
	s.rcache.InsertMessage(cache.Key(req.Question[0], dnssec, tcp), m)

	if err := w.WriteMsg(m); err != nil {
		log.Errorf("Failed to return reply %q", err)
	}
}

// ServeDNS is the handler for DNS requests, responsible for parsing DNS request, possibly forwarding
// it to a real dns server and returning a response.
func (s *server) serveDNS(w dns.ResponseWriter, req *dns.Msg) (tcp, dnssec bool, bufsize uint16, m *dns.Msg, err error) {
	m = new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = false
	m.RecursionAvailable = true
	m.Compress = true
	bufsize = uint16(512)

	q := req.Question[0]
	name := strings.ToLower(q.Name)

	if o := req.IsEdns0(); o != nil {
		bufsize = o.UDPSize()
		dnssec = o.Do()
	}
	if bufsize < 512 {
		bufsize = 512
	}
	// with TCP we can send 64K
	if tcp = isTCP(w); tcp {
		bufsize = dns.MaxMsgSize - 1
	}

	StatsRequestCount.Inc(1)

	if dnssec {
		StatsDnssecOkCount.Inc(1)
	}

	log.Debugf("[%d] Got query for '%s %s' from %s", req.Id, dns.TypeToString[q.Qtype], q.Name, w.RemoteAddr().String())

	// Check cache first.
	if m1 := s.rcache.Hit(q, dnssec, tcp, m.Id); m1 != nil {
		log.Debugf("[%d] Found cached response for this query", req.Id)
		if tcp {
			if _, overflow := Fit(m1, dns.MaxMsgSize, tcp); overflow {
				msgFail := new(dns.Msg)
				s.ServerFailure(msgFail, req)
				return tcp, dnssec, bufsize, msgFail, nil
			}
		} else {
			// Overflow with udp always results in TC.
			Fit(m1, int(bufsize), tcp)
		}
		if q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA {
			s.RoundRobin(m1.Answer)
		}
		StatsCacheHit.Inc(1)
		return tcp, dnssec, bufsize, m1, nil
	}

	StatsCacheMiss.Inc(1)

	// Check hosts records before forwarding the query
	if q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA || q.Qtype == dns.TypeANY {
		records, err := s.AddressRecords(q, name)
		if err != nil {
			log.Errorf("Error looking up hostsfile records: %s", err)
		}
		if len(records) > 0 {
			log.Debugf("[%d] Found name in hostsfile records", req.Id)
			m.Answer = append(m.Answer, records...)
			return tcp, dnssec, bufsize, m, nil
		}
	}

	if q.Qtype == dns.TypePTR && strings.HasSuffix(name, ".in-addr.arpa.") || strings.HasSuffix(name, ".ip6.arpa.") {
		return tcp, dnssec, bufsize, s.ServeDNSReverse(w, req), nil
	}

	if q.Qclass == dns.ClassCHAOS {
		m.Authoritative = true
		if q.Qtype == dns.TypeTXT {
			switch name {
			case "version.bind.":
				fallthrough
			case "version.server.":
				hdr := dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassCHAOS, Ttl: 0}
				m.Answer = []dns.RR{&dns.TXT{Hdr: hdr, Txt: []string{s.version}}}
				return tcp, dnssec, bufsize, m, nil
			case "hostname.bind.":
				fallthrough
			case "id.server.":
				// TODO(miek): machine name to return
				hdr := dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassCHAOS, Ttl: 0}
				m.Answer = []dns.RR{&dns.TXT{Hdr: hdr, Txt: []string{"localhost"}}}
				return tcp, dnssec, bufsize, m, nil
			}
		}
		// still here, fail
		m.SetReply(req)
		m.SetRcode(req, dns.RcodeServerFailure)
		return tcp, dnssec, bufsize, m, nil
	}

	// Forward all other queries
	return tcp, dnssec, bufsize, s.ServeDNSForward(w, req), nil
}

func (s *server) ServerFailure(m, req *dns.Msg) {
	m.SetRcode(req, dns.RcodeServerFailure)
}

func (s *server) RoundRobin(rrs []dns.RR) {
	if !s.config.RoundRobin {
		return
	}
	// If we have more than 1 CNAME don't touch the packet, because some stub resolver (=glibc)
	// can't deal with the returned packet if the CNAMEs need to be accesses in the reverse order.
	cname := 0
	for _, r := range rrs {
		if r.Header().Rrtype == dns.TypeCNAME {
			cname++
			if cname > 1 {
				return
			}
		}
	}

	switch l := len(rrs); l {
	case 2:
		if dns.Id()%2 == 0 {
			rrs[0], rrs[1] = rrs[1], rrs[0]
		}
	default:
		for j := 0; j < l*(int(dns.Id())%4+1); j++ {
			q := int(dns.Id()) % l
			p := int(dns.Id()) % l
			if q == p {
				p = (p + 1) % l
			}
			rrs[q], rrs[p] = rrs[p], rrs[q]
		}
	}

}

// isTCP returns true if the client is connecting over TCP.
func isTCP(w dns.ResponseWriter) bool {
	_, ok := w.RemoteAddr().(*net.TCPAddr)
	return ok
}
