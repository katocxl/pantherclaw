// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package sim

import (
	"net"
	"strings"
	"testing"
)

// TestDefaultAddrsUnique checks that no two simulators default to the same
// address, that every default is loopback, and that the usage text shows
// each subcommand's default.
func TestDefaultAddrsUnique(t *testing.T) {
	seen := map[string]string{}
	for name, addr := range defaultAddrs {
		if other, ok := seen[addr]; ok {
			t.Errorf("%s and %s both default to %s", name, other, addr)
		}
		seen[addr] = name
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			t.Errorf("%s: %s is not loopback", name, addr)
		}
		flagName := "--addr"
		if name == "canary" {
			flagName = "--query-addr"
		}
		if !strings.Contains(usageOf(name), "["+flagName+" "+addr+"]") {
			t.Errorf("usage of %s does not show [%s %s]", name, flagName, addr)
		}
	}
}

// usageOf is the usage text of one subcommand: its first line and the
// indented lines that continue it.
func usageOf(name string) string {
	var b strings.Builder
	in := false
	for _, line := range strings.Split(usage, "\n") {
		switch {
		case strings.HasPrefix(line, "  pantherclaw-sim "+name+" "):
			in = true
		case strings.HasPrefix(line, "  pantherclaw-sim "):
			in = false
		}
		if in {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	return b.String()
}
