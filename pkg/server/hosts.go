package server

import (
	"strings"

	"github.com/miekg/dns"
)

func (s *Server) AddressRecords(q dns.Question, name string) (records []dns.RR, err error) {
	results, err := s.hosts.FindHosts(name)
	if err != nil {
		return nil, err
	}

	for _, ip := range results {
		switch {
		case ip.To4() != nil && (q.Qtype == dns.TypeA || q.Qtype == dns.TypeANY):
			r := new(dns.A)
			r.Hdr = dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA,
				Class: dns.ClassINET, Ttl: s.config.HostsTtl}
			r.A = ip.To4()
			records = append(records, r)
		case ip.To4() == nil && (q.Qtype == dns.TypeAAAA || q.Qtype == dns.TypeANY):
			r := new(dns.AAAA)
			r.Hdr = dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA,
				Class: dns.ClassINET, Ttl: s.config.HostsTtl}
			r.AAAA = ip.To16()
			records = append(records, r)
		}
	}
	return records, nil
}

func (s *Server) PTRRecords(q dns.Question) (records []dns.RR, err error) {
	name := strings.ToLower(q.Name)
	result, err := s.hosts.FindReverse(name)
	if err != nil {
		return nil, err
	}
	if result != "" {
		r := new(dns.PTR)
		r.Hdr = dns.RR_Header{Name: q.Name, Rrtype: dns.TypePTR,
			Class: dns.ClassINET, Ttl: s.config.HostsTtl}
		r.Ptr = result
		records = append(records, r)
	}
	return records, nil
}
