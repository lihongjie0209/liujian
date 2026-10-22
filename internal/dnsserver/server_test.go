package dnsserver

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/lihongjie0209/liujian/internal/allowlist"
	"github.com/miekg/dns"
)

func TestAllowHostsOnlyRewritesMatchingDNSAnswers(t *testing.T) {
	upstreamPacket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstream := &dns.Server{PacketConn: upstreamPacket, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		answer := new(dns.Msg).SetReply(q)
		ip := net.IPv4(203, 0, 113, 10)
		if q.Question[0].Name == "other.test." {
			ip = net.IPv4(198, 51, 100, 10)
		}
		answer.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: ip}}
		_ = w.WriteMsg(answer)
	})}
	go func() { _ = upstream.ActivateAndServe() }()
	defer upstream.Shutdown()
	hosts, err := allowlist.ParseHosts([]string{"allowed.test", "203.0.113.10"})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	s := &Server{ListenIP: net.IPv4(127, 0, 0, 1), Port: port, Upstream: upstreamPacket.LocalAddr().String(), AllowHosts: hosts}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Shutdown()
	for _, tc := range []struct{ name, want string }{
		{"allowed.test.", "127.0.0.1"},
		{"ipmatch.test.", "127.0.0.1"},
		{"other.test.", "198.51.100.10"},
	} {
		answer, _, err := (&dns.Client{Timeout: time.Second}).Exchange(new(dns.Msg).SetQuestion(tc.name, dns.TypeA), fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			t.Fatal(err)
		}
		if got := answer.Answer[0].(*dns.A).A.String(); got != tc.want {
			t.Errorf("%s = %s, want %s", tc.name, got, tc.want)
		}
	}
}

func TestWildcardListenerAnswersWithReachableIP(t *testing.T) {
	portListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := portListener.Addr().(*net.TCPAddr).Port
	portListener.Close()

	s := &Server{ListenIP: net.IPv4zero, Port: port, Upstream: "8.8.8.8:53"}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	defer s.Shutdown()
	for _, network := range []string{"udp", "tcp"} {
		t.Run(network, func(t *testing.T) {
			query := new(dns.Msg).SetQuestion("ca-proxy.test.", dns.TypeA)
			client := &dns.Client{Net: network, Timeout: time.Second}
			answer, _, err := client.Exchange(query, net.JoinHostPort("127.0.0.1", fmt.Sprint(port)))
			if err != nil {
				t.Fatal(err)
			}
			if len(answer.Answer) != 1 {
				t.Fatalf("DNS answer = %v", answer.Answer)
			}
			a, ok := answer.Answer[0].(*dns.A)
			if !ok || !a.A.Equal(net.IPv4(127, 0, 0, 1)) {
				t.Fatalf("DNS A record = %v, want 127.0.0.1", answer.Answer[0])
			}
		})
	}
}

func TestChooseAnswerIP(t *testing.T) {
	interfaces := []net.IPNet{
		interfaceCIDR(t, "192.168.1.20/24"),
		interfaceCIDR(t, "10.0.0.8/8"),
		interfaceCIDR(t, "10.1.2.3/24"),
	}
	rules, err := ParseAnswerRules([]string{"172.16.0.0/12=192.168.1.20", "172.16.2.0/24=10.1.2.3", "10.1.2.0/24=192.168.1.20"})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, client, listen, want string
		rules                      []AnswerRule
	}{
		{name: "same subnet", client: "192.168.1.50", listen: "0.0.0.0", want: "192.168.1.20"},
		{name: "longest interface subnet", client: "10.1.2.55", listen: "0.0.0.0", want: "10.1.2.3"},
		{name: "specific listener", client: "192.168.1.50", listen: "10.0.0.8"},
		{name: "no matching subnet", client: "172.16.1.4", listen: "0.0.0.0"},
		{name: "explicit rule", client: "172.16.1.4", listen: "0.0.0.0", rules: rules, want: "192.168.1.20"},
		{name: "longest explicit rule", client: "172.16.2.4", listen: "0.0.0.0", rules: rules, want: "10.1.2.3"},
		{name: "explicit beats automatic", client: "10.1.2.55", listen: "0.0.0.0", rules: rules, want: "192.168.1.20"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			answer := chooseAnswerIP(&net.UDPAddr{IP: net.ParseIP(tt.client), Port: 12345}, net.ParseIP(tt.listen), interfaces, tt.rules)
			if got := answer.String(); got != tt.want && !(answer == nil && tt.want == "") {
				t.Fatalf("answer IP = %s, want %q", got, tt.want)
			}
		})
	}
}

func TestParseAnswerRulesRejectsInvalidRules(t *testing.T) {
	for _, raw := range [][]string{
		{"not-a-rule"},
		{"192.168.1.0/24=not-an-ip"},
		{"192.168.1.0/24=0.0.0.0"},
		{"192.168.1.0/24=192.168.1.20", "192.168.1.1/24=192.168.1.21"},
	} {
		if _, err := ParseAnswerRules(raw); err == nil {
			t.Errorf("accepted invalid rules %v", raw)
		}
	}
}

func TestAnswerRuleMustUseLocalListeningAddress(t *testing.T) {
	rules, err := ParseAnswerRules([]string{"192.168.1.0/24=8.8.8.8"})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{ListenIP: net.IPv4zero, Port: 10053, Upstream: "1.1.1.1:53", AnswerRules: rules}
	if err := s.Start(); err == nil || !strings.Contains(err.Error(), "not assigned to a local interface") {
		t.Fatalf("nonlocal DNS answer was accepted: %v", err)
	}
}

func interfaceCIDR(t *testing.T, value string) net.IPNet {
	t.Helper()
	ip, subnet, err := net.ParseCIDR(value)
	if err != nil {
		t.Fatal(err)
	}
	return net.IPNet{IP: ip, Mask: subnet.Mask}
}
