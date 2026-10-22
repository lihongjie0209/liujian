package allowlist

import (
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/net/idna"
)

type Hosts struct {
	exact     map[string]bool
	suffixes  []string
	addresses []netip.Prefix
}

func ParseHosts(values []string) (Hosts, error) {
	hosts := Hosts{exact: make(map[string]bool)}
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			return Hosts{}, fmt.Errorf("empty allow-host entry")
		}
		if prefix, err := netip.ParsePrefix(value); err == nil {
			hosts.addresses = append(hosts.addresses, prefix.Masked())
			continue
		}
		if ip, err := netip.ParseAddr(value); err == nil {
			hosts.addresses = append(hosts.addresses, netip.PrefixFrom(ip.Unmap(), ip.Unmap().BitLen()))
			continue
		}
		if strings.ContainsAny(value, "/:") {
			return Hosts{}, fmt.Errorf("invalid allow-host %q", raw)
		}
		wildcard := strings.HasPrefix(value, "*.")
		if wildcard {
			value = value[2:]
		}
		name, err := idna.Lookup.ToASCII(strings.TrimSuffix(strings.ToLower(value), "."))
		if err != nil || !validDomain(name) {
			return Hosts{}, fmt.Errorf("invalid allow-host %q", raw)
		}
		if wildcard {
			hosts.suffixes = append(hosts.suffixes, "."+name)
		} else {
			hosts.exact[name] = true
		}
	}
	return hosts, nil
}

func (h Hosts) Enabled() bool {
	return len(h.exact)+len(h.suffixes)+len(h.addresses) > 0
}

func (h Hosts) HasIPs() bool { return len(h.addresses) > 0 }

func (h Hosts) Match(host string) bool {
	if !h.Enabled() {
		return true
	}
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if ip, err := netip.ParseAddr(host); err == nil {
		return h.MatchIP(ip)
	}
	name, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return false
	}
	if h.exact[name] {
		return true
	}
	for _, suffix := range h.suffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

func (h Hosts) MatchIP(ip netip.Addr) bool {
	if !h.Enabled() {
		return true
	}
	ip = ip.Unmap()
	for _, prefix := range h.addresses {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func validDomain(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '-' {
				return false
			}
		}
	}
	return true
}

type Clients struct{ networks []netip.Prefix }

func (c Clients) Enabled() bool { return len(c.networks) > 0 }

func ParseClients(values []string) (Clients, error) {
	var clients Clients
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if prefix, err := netip.ParsePrefix(value); err == nil {
			clients.networks = append(clients.networks, prefix.Masked())
			continue
		}
		if ip, err := netip.ParseAddr(value); err == nil {
			ip = ip.Unmap()
			clients.networks = append(clients.networks, netip.PrefixFrom(ip, ip.BitLen()))
			continue
		}
		return Clients{}, fmt.Errorf("invalid allow-client %q; expected IP or CIDR", raw)
	}
	return clients, nil
}

func (c Clients) Match(ip netip.Addr) bool {
	if len(c.networks) == 0 {
		return true
	}
	ip = ip.Unmap()
	for _, prefix := range c.networks {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}
