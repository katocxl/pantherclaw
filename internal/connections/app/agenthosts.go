// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"net/netip"
	"regexp"
	"slices"

	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
)

// maxAgentHosts bounds a connection's agent hosts (00090).
const maxAgentHosts = 16

// ErrAgentHosts is an invalid list of agent hosts.
var ErrAgentHosts = pcerr.New(pcerr.InvalidArgument, "AGENT_HOSTS_INVALID",
	"agent hosts are up to 16 distinct lowercase host names, no IP address, and only on http and mcp connections")

var agentHostRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)

// checkAgentHosts checks the host names agents use for a connection's API
// (G0 M9): the sandbox's edge maps each to the connection, so a change to
// them is a weakening change (HR-183). Only connections the gateway
// dispatches over HTTP have them. The database checks the same (00090).
func checkAgentHosts(kind string, hosts []string) ([]string, error) {
	if len(hosts) == 0 {
		return []string{}, nil
	}
	if (kind != KindHTTP && kind != KindMCP) || len(hosts) > maxAgentHosts {
		return nil, ErrAgentHosts
	}
	for i, h := range hosts {
		if _, err := netip.ParseAddr(h); err == nil || !agentHostRE.MatchString(h) || slices.Contains(hosts[:i], h) {
			return nil, ErrAgentHosts
		}
	}
	return slices.Clone(hosts), nil
}
