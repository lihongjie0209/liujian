package allowlist

import (
	"net/netip"
	"testing"
)

func TestHosts(t *testing.T) {
	hosts, err := ParseHosts([]string{"API.Example.test", "*.example.test", "localhost", "192.0.2.8", "198.51.100.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		host string
		want bool
	}{
		{"api.example.test", true},
		{"a.example.test", true},
		{"example.test", false},
		{"badexample.test", false},
		{"localhost", true},
		{"192.0.2.8", true},
		{"198.51.100.42", true},
		{"203.0.113.1", false},
	} {
		if got := hosts.Match(tc.host); got != tc.want {
			t.Errorf("Match(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
	for _, raw := range []string{"", "https://example.test", "*.bad_thing.test", "192.0.2.0/99"} {
		if _, err := ParseHosts([]string{raw}); err == nil {
			t.Errorf("accepted invalid host %q", raw)
		}
	}
}

func TestClients(t *testing.T) {
	clients, err := ParseClients([]string{"192.168.20.0/22", "10.0.0.2"})
	if err != nil {
		t.Fatal(err)
	}
	if !clients.Match(netip.MustParseAddr("192.168.22.126")) || !clients.Match(netip.MustParseAddr("10.0.0.2")) {
		t.Fatal("allowed client was rejected")
	}
	if clients.Match(netip.MustParseAddr("192.168.24.1")) {
		t.Fatal("outside client was accepted")
	}
	if _, err := ParseClients([]string{"not-an-ip"}); err == nil {
		t.Fatal("accepted invalid client")
	}
}
