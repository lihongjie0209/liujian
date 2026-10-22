package dnsserver

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/lihongjie0209/liujian/internal/allowlist"
	"github.com/miekg/dns"
)

// AnswerRule maps DNS clients in a CIDR to an IPv4 address served by this host.
type AnswerRule struct {
	ClientNet *net.IPNet
	AnswerIP  net.IP
}

type Server struct {
	ListenIP     net.IP
	Port         int
	Upstream     string
	Exclude      []string
	AllowHosts   allowlist.Hosts
	AllowClients allowlist.Clients
	AnswerRules  []AnswerRule
	UDP          *dns.Server
	TCP          *dns.Server
	Errors       chan error
	interfaces   []net.IPNet
}

// ParseAnswerRules parses repeatable CLIENT_CIDR=ANSWER_IP settings.
func ParseAnswerRules(raw []string) ([]AnswerRule, error) {
	rules := make([]AnswerRule, 0, len(raw))
	seen := make(map[string]bool, len(raw))
	for _, value := range raw {
		client, answer, ok := strings.Cut(value, "=")
		_, network, err := net.ParseCIDR(strings.TrimSpace(client))
		ip := net.ParseIP(strings.TrimSpace(answer)).To4()
		if !ok || err != nil || network.IP.To4() == nil || ip == nil || ip.IsUnspecified() {
			return nil, fmt.Errorf("invalid DNS answer rule %q; expected IPv4_CIDR=LOCAL_IP", value)
		}
		key := network.String()
		if seen[key] {
			return nil, fmt.Errorf("duplicate DNS answer rule for %s", key)
		}
		seen[key] = true
		rules = append(rules, AnswerRule{ClientNet: network, AnswerIP: ip})
	}
	sort.Slice(rules, func(i, j int) bool {
		iBits, _ := rules[i].ClientNet.Mask.Size()
		jBits, _ := rules[j].ClientNet.Mask.Size()
		return iBits > jBits
	})
	return rules, nil
}

func (s *Server) Start() error {
	if s.ListenIP == nil || s.ListenIP.To4() == nil {
		return fmt.Errorf("DNS listen IP must be IPv4")
	}
	if _, _, err := net.SplitHostPort(s.Upstream); err != nil {
		return fmt.Errorf("upstream DNS: %w", err)
	}
	if s.Port == 0 {
		s.Port = 53
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return fmt.Errorf("list network interfaces: %w", err)
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil {
			s.interfaces = append(s.interfaces, net.IPNet{IP: ipNet.IP.To4(), Mask: ipNet.Mask})
		}
	}
	for _, rule := range s.AnswerRules {
		if rule.ClientNet == nil || rule.AnswerIP.To4() == nil || rule.AnswerIP.IsUnspecified() {
			return fmt.Errorf("invalid DNS answer rule")
		}
		if !s.ListenIP.IsUnspecified() && !s.ListenIP.Equal(rule.AnswerIP) {
			return fmt.Errorf("DNS answer %s differs from listen IP %s", rule.AnswerIP, s.ListenIP)
		}
		found := false
		for _, iface := range s.interfaces {
			found = found || iface.IP.Equal(rule.AnswerIP)
		}
		if !found {
			return fmt.Errorf("DNS answer %s is not assigned to a local interface", rule.AnswerIP)
		}
	}
	addr := net.JoinHostPort(s.ListenIP.String(), fmt.Sprint(s.Port))
	h := dns.HandlerFunc(s.handle)
	s.UDP = &dns.Server{Addr: addr, Net: "udp", Handler: h, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second}
	s.TCP = &dns.Server{Addr: addr, Net: "tcp", Handler: h, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second}
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		pc.Close()
		return err
	}
	s.UDP.PacketConn = pc
	s.TCP.Listener = ln
	s.Errors = make(chan error, 2)
	go func() {
		if err := s.UDP.ActivateAndServe(); err != nil {
			s.Errors <- fmt.Errorf("DNS UDP: %w", err)
		}
	}()
	go func() {
		if err := s.TCP.ActivateAndServe(); err != nil {
			s.Errors <- fmt.Errorf("DNS TCP: %w", err)
		}
	}()
	return nil
}

func (s *Server) Shutdown() {
	if s.UDP != nil {
		_ = s.UDP.Shutdown()
	}
	if s.TCP != nil {
		_ = s.TCP.Shutdown()
	}
}

func (s *Server) handle(w dns.ResponseWriter, q *dns.Msg) {
	if len(q.Question) != 1 {
		_ = w.WriteMsg(new(dns.Msg).SetRcode(q, dns.RcodeFormatError))
		return
	}
	question := q.Question[0]
	name := strings.TrimSuffix(strings.ToLower(question.Name), ".")
	if question.Qclass != dns.ClassINET || (s.excluded(name) && name != "ca-proxy.test") {
		s.forward(w, q)
		return
	}
	if name != "ca-proxy.test" && !s.clientAllowed(w.RemoteAddr()) {
		s.forward(w, q)
		return
	}
	if name != "ca-proxy.test" && !s.AllowHosts.Match(name) && question.Qtype != dns.TypeA {
		s.forward(w, q)
		return
	}
	var answerIP net.IP
	if question.Qtype == dns.TypeA {
		answerIP = chooseAnswerIP(w.RemoteAddr(), s.ListenIP, s.interfaces, s.AnswerRules)
		if answerIP == nil {
			_ = w.WriteMsg(new(dns.Msg).SetRcode(q, dns.RcodeServerFailure))
			return
		}
	}
	if name == "ca-proxy.test" {
		msg := new(dns.Msg).SetReply(q)
		if question.Qtype == dns.TypeA {
			msg.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 5}, A: answerIP}}
		}
		_ = w.WriteMsg(msg)
		return
	}
	switch question.Qtype {
	case dns.TypeA:
		up, err := s.exchange(q)
		if err != nil {
			_ = w.WriteMsg(new(dns.Msg).SetRcode(q, dns.RcodeServerFailure))
			return
		}
		if up.Rcode != dns.RcodeSuccess {
			_ = w.WriteMsg(up)
			return
		}
		if !s.allowedAnswer(name, up) {
			_ = w.WriteMsg(up)
			return
		}
		msg := new(dns.Msg).SetReply(q)
		msg.RecursionAvailable = true
		msg.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 5}, A: answerIP}}
		_ = w.WriteMsg(msg)
	case dns.TypeAAAA, dns.TypeHTTPS, dns.TypeSVCB:
		msg := new(dns.Msg).SetReply(q)
		msg.RecursionAvailable = true
		_ = w.WriteMsg(msg)
	default:
		s.forward(w, q)
	}
}

func (s *Server) clientAllowed(remote net.Addr) bool {
	var ip net.IP
	switch addr := remote.(type) {
	case *net.UDPAddr:
		ip = addr.IP
	case *net.TCPAddr:
		ip = addr.IP
	}
	if parsed, ok := netip.AddrFromSlice(ip); ok {
		return s.AllowClients.Match(parsed)
	}
	return false
}

func (s *Server) allowedAnswer(name string, upstream *dns.Msg) bool {
	if s.AllowHosts.Match(name) {
		return true
	}
	for _, answer := range upstream.Answer {
		if record, ok := answer.(*dns.A); ok {
			if ip, valid := netip.AddrFromSlice(record.A); valid && s.AllowHosts.MatchIP(ip) {
				return true
			}
		}
	}
	return false
}

func chooseAnswerIP(remote net.Addr, listenIP net.IP, interfaces []net.IPNet, rules []AnswerRule) net.IP {
	var client net.IP
	switch addr := remote.(type) {
	case *net.UDPAddr:
		client = addr.IP.To4()
	case *net.TCPAddr:
		client = addr.IP.To4()
	}
	if client == nil {
		return nil
	}
	for _, rule := range rules {
		if rule.ClientNet.Contains(client) {
			return rule.AnswerIP.To4()
		}
	}
	bestBits := -1
	ambiguous := false
	var answer net.IP
	for _, iface := range interfaces {
		if !listenIP.IsUnspecified() && !listenIP.Equal(iface.IP) {
			continue
		}
		if !iface.Contains(client) {
			continue
		}
		bits, _ := iface.Mask.Size()
		if bits > bestBits {
			bestBits, answer = bits, iface.IP.To4()
			ambiguous = false
		} else if bits == bestBits && !answer.Equal(iface.IP) {
			ambiguous = true
		}
	}
	if ambiguous {
		return nil
	}
	return answer
}

func (s *Server) excluded(name string) bool {
	for _, raw := range s.Exclude {
		p := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
		if p == name || (strings.HasPrefix(p, "*.") && strings.HasSuffix(name, p[1:]) && len(name) > len(p)-1) {
			return true
		}
	}
	return false
}

func (s *Server) forward(w dns.ResponseWriter, q *dns.Msg) {
	msg, err := s.exchange(q)
	if err != nil {
		msg = new(dns.Msg).SetRcode(q, dns.RcodeServerFailure)
	}
	_ = w.WriteMsg(msg)
}

func (s *Server) exchange(q *dns.Msg) (*dns.Msg, error) {
	client := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
	msg, _, err := client.Exchange(q, s.Upstream)
	if err != nil {
		return nil, err
	}
	if msg.Truncated {
		client.Net = "tcp"
		msg, _, err = client.Exchange(q, s.Upstream)
	}
	return msg, err
}

func Resolver(upstream string) *net.Resolver {
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, upstream)
	}}
}
