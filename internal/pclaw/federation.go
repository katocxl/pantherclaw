// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"errors"
)

// pclaw federation … (G0 M35 D1046): an org's federation document, its
// key, its pairwise trusts with peer orgs (FD10), its listings (the agents
// a trusted peer may message), cross-org grants and the minimal receipts
// both sides keep. Trust confirmation and key rotation need a person's
// security key (D1020, D1021), which the console's confirm page does.

// errFederationUnwired answers a federation command before its RPCs exist.
var errFederationUnwired = errors.New("federation: not available in this build")

// federationUsage is each command's usage, by command name.
var federationUsage = map[string]string{
	"federation doc":            "federation doc",
	"federation endpoint":       "federation endpoint URL   (the gateway's public base URL peers call)",
	"federation rotate":         "federation rotate   (needs your security key; the old key stays RETIRING 7 days)",
	"federation trust propose":  "federation trust propose PEER_DOC_URL   (https; shows the safety code to compare)",
	"federation trust confirm":  "federation trust confirm TRUST_ID   (needs your security key; compare the safety code first)",
	"federation trust revoke":   "federation trust revoke TRUST_ID",
	"federation trust list":     "federation trust list",
	"federation trust show":     "federation trust show TRUST_ID",
	"federation listing create": "federation listing create NAME --agent AGENT_ID --connection CONNECTION_ID [--skill ID]...",
	"federation listing retire": "federation listing retire LISTING_ID",
	"federation peers":          "federation peers TRUST_ID   (the peer's listed agents and whether each verifies)",
	"federation grant issue": "federation grant issue TRUST_ID --peer-agent SUB --listing NAME --op OP... " +
		"[--min-attestation N] [--limit name=value]... --expires-at RFC3339   (at most 90 days)",
	"federation grant revoke": "federation grant revoke GRANT_ID",
	"federation receipts":     "federation receipts [--direction in|out] [--peer ORG_ID] [--action ACTION_ID]",
}

// federationCommands are the pclaw federation commands; their RPCs land
// with FederationService.
func federationCommands() map[string]command {
	out := make(map[string]command, len(federationUsage))
	for name, usage := range federationUsage {
		out[name] = command{usage: usage, run: func(context.Context, *app, []string) error {
			return errFederationUnwired
		}}
	}
	return out
}
