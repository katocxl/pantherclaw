// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package httpx

import (
	"net/netip"
	"strconv"
	"strings"
)

// metadataAddrs are cloud instance-metadata and platform endpoints. They are
// refused even inside an operator's allowed prefixes (HR-077).
var metadataAddrs = []netip.Addr{
	netip.MustParseAddr("169.254.169.254"), // AWS, GCP, Azure, OCI, DigitalOcean, OpenStack
	netip.MustParseAddr("169.254.169.253"), // AWS DNS
	netip.MustParseAddr("169.254.170.2"),   // AWS ECS task metadata
	netip.MustParseAddr("169.254.170.23"),  // AWS EKS Pod Identity
	netip.MustParseAddr("100.100.100.200"), // Alibaba Cloud
	netip.MustParseAddr("168.63.129.16"),   // Azure WireServer
	netip.MustParseAddr("fd00:ec2::254"),   // AWS IMDS over IPv6
	netip.MustParseAddr("fd00:ec2::23"),    // AWS EKS Pod Identity over IPv6
}

// metadataNames are host names of metadata services.
var metadataNames = []string{
	"metadata", "metadata.google.internal", "metadata.goog", "instance-data", "instance-data.ec2.internal",
	"metadata.azure.com", "metadata.tencentyun.com", "metadata.platformequinix.com",
}

// MetadataAddr reports whether a is a cloud metadata endpoint, in any form
// that carries it (IPv4-mapped, NAT64, 6to4, Teredo).
func MetadataAddr(a netip.Addr) bool {
	a = a.WithZone("")
	for _, m := range metadataAddrs {
		if a == m {
			return true
		}
	}
	for _, v4 := range embeddedIPv4(a) {
		if MetadataAddr(v4) {
			return true
		}
	}
	return false
}

// MetadataHost reports whether a host name names a metadata service.
func MetadataHost(host string) bool {
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	for _, n := range metadataNames {
		if h == n {
			return true
		}
	}
	return false
}

// DeniedHost reports whether a URL's host, as written, is a destination the
// egress client refuses, before any lookup: an IP address in any spelling
// HostAddr reads that DeniedAddr denies with the allowed prefixes, or a
// metadata service's name. Other names can only be checked when they are
// dialled, which the egress client does (HR-071, HR-077).
func DeniedHost(host string, allowed []netip.Prefix) bool {
	if a, ok := HostAddr(host); ok {
		return DeniedAddr(a, allowed)
	}
	return MetadataHost(host)
}

// HostAddr parses host as an IP address in any spelling a resolver might
// accept: dotted quads, IPv6 (with or without brackets), and the inet_aton
// forms of IPv4 (one to four parts, each decimal, octal with a leading 0 or
// hexadecimal with 0x), so that 2852039166, 0xa9fea9fe and 0251.0376.0251.0376
// are all 169.254.169.254. ok is false for a host name.
func HostAddr(host string) (netip.Addr, bool) {
	h := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSuffix(host, "]"), "["), ".")
	if a, err := netip.ParseAddr(h); err == nil {
		return a.WithZone(""), true
	}
	parts := strings.Split(h, ".")
	if len(parts) == 0 || len(parts) > 4 {
		return netip.Addr{}, false
	}
	vals := make([]uint64, len(parts))
	for i, p := range parts {
		v, ok := atonPart(p)
		if !ok {
			return netip.Addr{}, false
		}
		vals[i] = v
	}
	// The last part fills the remaining bytes (a.b.c.d, a.b.cd, a.bcd, abcd).
	var n uint64
	for i, v := range vals[:len(vals)-1] {
		if v > 0xff {
			return netip.Addr{}, false
		}
		n |= v << (8 * (3 - uint(i)))
	}
	last := vals[len(vals)-1]
	if last >= 1<<(8*(5-uint(len(vals)))) {
		return netip.Addr{}, false
	}
	n |= last
	return netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}), true //nolint:gosec // G115: n < 2^32 by construction
}

func atonPart(p string) (uint64, bool) {
	if p == "" {
		return 0, false
	}
	base := 10
	switch {
	case strings.HasPrefix(p, "0x") || strings.HasPrefix(p, "0X"):
		base, p = 16, p[2:]
		if p == "" {
			return 0, true
		}
	case len(p) > 1 && p[0] == '0':
		base, p = 8, p[1:]
	}
	v, err := strconv.ParseUint(p, base, 32)
	return v, err == nil
}
