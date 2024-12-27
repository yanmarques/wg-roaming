package main

import (
	"net"
	"testing"
)

func TestAllocteIP(t *testing.T) {
	testCIDR := "172.16.0.0/30"
	usedIPs := map[string]interface{}{
		"172.16.0.1": 0,
		"172.16.0.2": 0,
	}

	_, testSubnet, err := net.ParseCIDR(testCIDR)
	if err != nil {
		t.Fatalf("failed to parse test CIDR")
	}

	ip := testSubnet.IP.Mask(testSubnet.Mask)
	broadcastAddr := getBroadcastAddress(testSubnet)
	ip[len(ip)-1]++

	for ; testSubnet.Contains(ip); incrementIP(ip) {
		_, used := usedIPs[ip.String()]
		if !used {
			break
		}
	}

	if ip.Equal(broadcastAddr) {
		t.Log("is broadcast addr", broadcastAddr.String())
	}

	_, alreadyUsed := usedIPs[ip.String()]
	if alreadyUsed {
		t.Fatalf("no more available ips")
	}

	expected := "172.16.0.2"
	if ip.String() != expected {
		t.Fatalf("wrong ip, expected=%s ip=%s", expected, ip.String())
	}
}
