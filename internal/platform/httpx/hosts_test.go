// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package httpx

import (
	"net/netip"
	"testing"
)

// TestHR077_MetadataInAnySpelling: every spelling of a metadata address is
// recognized, and metadata stays denied inside an allowed prefix.
func TestHR077_MetadataInAnySpelling(t *testing.T) {
	for _, host := range []string{
		"169.254.169.254", "2852039166", "0xa9fea9fe", "0xA9.0xFE.0xA9.0xFE", "0251.0376.0251.0376", "169.254.43518",
		"169.16689662", "[::ffff:169.254.169.254]", "::ffff:a9fe:a9fe", "[fd00:ec2::254]", "100.100.100.200",
		"169.254.169.254.", "64:ff9b::a9fe:a9fe",
	} {
		a, ok := HostAddr(host)
		if !ok || !MetadataAddr(a) {
			t.Errorf("%s: %v %v", host, a, ok)
		}
		if !DeniedAddr(a, []netip.Prefix{netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("::/0")}) {
			t.Errorf("%s is allowed through an allowed prefix", host)
		}
	}
	for _, host := range []string{"10.0.0.5", "127.0.0.1", "8.8.8.8", "2001:4860::8888", "017.0.0.1"} {
		a, ok := HostAddr(host)
		if !ok || MetadataAddr(a) {
			t.Errorf("%s: %v %v", host, a, ok)
		}
	}
	if a, _ := HostAddr("017.0.0.1"); a != netip.MustParseAddr("15.0.0.1") {
		t.Errorf("octal 017.0.0.1 = %v", a)
	}
	for _, host := range []string{"example.com", "api.internal", "1e100", "256.1.1.1", "1.2.3.4.5", "1.2.65536", ""} {
		if a, ok := HostAddr(host); ok {
			t.Errorf("%s parsed as %v", host, a)
		}
	}
	for _, name := range []string{"metadata.google.internal", "METADATA.google.internal.", "instance-data", "metadata"} {
		if !MetadataHost(name) {
			t.Errorf("%s is not a metadata host", name)
		}
	}
	if MetadataHost("metadata.example.com") {
		t.Error("an ordinary host is a metadata host")
	}
}

// TestHR077_DeniedHostReadsTheHostAsTheGuardDoes: a host as written is
// denied when it spells a denied address in any form, or names a metadata
// service; an allowed prefix re-allows a private address but never
// metadata; other names are left to the dial-time check.
func TestHR077_DeniedHostReadsTheHostAsTheGuardDoes(t *testing.T) {
	private := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16")}
	for host, deniedWithPrivate := range map[string]bool{
		"0xa9fea9fe": true, "2852039166": true, "[::ffff:a9fe:a9fe]": true, "metadata.google.internal.": true,
		"2130706433": true, "0x7f.1": true, "0": true, "167772165": false, "0xa.0.0.5": false,
	} {
		if !DeniedHost(host, nil) {
			t.Errorf("%s is not denied", host)
		}
		if got := DeniedHost(host, private); got != deniedWithPrivate {
			t.Errorf("%s with allowed private ranges: denied=%v, want %v", host, got, deniedWithPrivate)
		}
	}
	for _, host := range []string{"hooks.example.com", "metadata.example.com", "8.8.8.8", "134744072", "[2001:4860::8888]"} {
		if DeniedHost(host, nil) {
			t.Errorf("%s is denied", host)
		}
	}
}
