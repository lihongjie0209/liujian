package netutil

import (
	"fmt"
	"net"
)

// LocalPrivateIPv4 returns the host's non-loopback private IPv4 addresses.
func LocalPrivateIPv4() ([]net.IP, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, fmt.Errorf("list network interfaces: %w", err)
	}
	var ips []net.IP
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP.To4()
		if ip != nil && ip.IsPrivate() && !ip.IsLoopback() {
			ips = append(ips, ip)
		}
	}
	return ips, nil
}

// IsLocalIPv4 reports whether ip belongs to any of this host's interfaces.
func IsLocalIPv4(ip net.IP) (bool, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false, fmt.Errorf("list network interfaces: %w", err)
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.Equal(ip) {
			return true, nil
		}
	}
	return false, nil
}

// ConflictsWithListener checks whether an upstream DNS address reaches this listener.
func ConflictsWithListener(listenIP, upstreamIP net.IP) (bool, error) {
	if listenIP.Equal(upstreamIP) {
		return true, nil
	}
	if !listenIP.IsUnspecified() {
		return false, nil
	}
	return IsLocalIPv4(upstreamIP)
}
