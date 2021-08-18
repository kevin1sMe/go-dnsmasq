package server

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"

	"github.com/soulteary/go-dnsmasq/pkg/cache"
	hosts "github.com/soulteary/go-dnsmasq/pkg/hostsfile"
	"github.com/soulteary/go-dnsmasq/pkg/log"
)

func init() {
	if err := log.New("info"); err != nil {
		log.Fatal("fail to init logger: ", err)
	}
}

func TestPluggable(t *testing.T) {
	tests := []struct {
		name       string
		pluggable  PluggableFunc
		question   string
		wantAnswer string
		wantErr    string
	}{
		{
			name:     "use pluggable func",
			question: "tomoyamachi.com",
			pluggable: func(m *dns.Msg, q dns.Question, targetName string, isTCP bool) (*dns.Msg, error) {
				r := new(dns.A)
				r.Hdr = dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA,
					Class: dns.ClassINET, Ttl: 10}
				r.A = net.ParseIP("1.1.1.1")
				m.Answer = append(m.Answer, r)
				return m, nil
			},
			wantAnswer: "tomoyamachi.com	10	IN	A	1.1.1.1",
		},
		{
			name:     "no pluggable func, load from hostfile",
			question: "tomoyamachi.com",
			wantAnswer: "tomoyamachi.com	10	IN	A	111.11.11.11",
		},
	}

	hostfile, _ := hosts.NewHostsfile("./golden/hosts.golden", &hosts.Config{Poll: time.Second})
	for _, tc := range tests {
		server := Server{
			hosts:         hostfile,
			rcache:        cache.New(1, time.Second),
			config:        &Config{HostsTtl: 10},
			pluggableFunc: nil,
		}
		if tc.pluggable != nil {
			server.pluggableFunc = &tc.pluggable
		}
		rw := NewWriter("udp", "127.0.0.1:0")
		msg := new(dns.Msg)
		msg.Compress = true
		msg.SetQuestion(tc.question, dns.TypeANY)
		_, _, _, m, err := server.serveDNS(rw, msg)
		if tc.wantErr != "" {
			assert.EqualError(t, err, tc.wantErr, tc.name)
			continue
		}
		if !assert.NoError(t, err, tc.name) {
			continue
		}
		if len(m.Answer) == 0 {
			assert.Equal(t, tc.wantAnswer, "", tc.name, "no answer")
		}
		assert.Equal(t, m.Answer[0].String(), tc.wantAnswer, tc.name)

	}

}
