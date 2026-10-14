// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package sandbox

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// TestHR214_TheEdgeLogGivesTheAgentsRoutesOnly: from the edge's log, the
// session reports each destination the edge refused the agent and each
// credential it stripped from the agent's requests (kind and SHA-256
// prefix), once each and at most MaxRoutes. The probe's own refused
// requests, from another address, and lines that are not edge events are
// left out; an agent whose address was not read (it exited at once) is
// told by the log after its start.
func TestHR214_TheEdgeLogGivesTheAgentsRoutesOnly(t *testing.T) {
	const agent, probe = "10.89.0.3", "10.89.0.4"
	log := strings.Join([]string{
		`{"event":"edge.ready","ca_pem":"x"}`,
		`{"event":"edge.refused","client":"` + probe + `","destination":"unmapped.invalid:443","code":"unmapped_host"}`,
		`{"event":"edge.refused","client":"` + probe + `","destination":"github.com:443","code":"unmapped_host"}`,
		`{"event":"edge.refused","client":"` + agent + `","destination":"pypi.org:443","code":"unmapped_host"}`,
		`{"event":"edge.refused","client":"` + agent + `","destination":"pypi.org:443","code":"unmapped_host"}`,
		`{"event":"edge.credential_stripped","client":"` + agent + `","header":"Authorization","kind":"github_pat","sha256_prefix":"0a1b2c3d4e5f","destination":"api.github.com"}`,
		`{"event":"edge.forwarded","client":"` + agent + `","connection":"github"}`,
		`not json`,
		`{"event":"edge.refused","client":"` + agent + `","destination":""}`,
	}, "\n")
	got := edgeRoutes([]byte(log), agent)
	want := []Route{{RouteDirectAPI, "pypi.org:443"}, {RouteCredential, "github_pat:0a1b2c3d4e5f"}}
	if !slices.Equal(got, want) {
		t.Fatalf("routes %v, want %v", got, want)
	}
	// From the agent's start on, every client's request is the agent's: an
	// agent that exited before its address was read is still told.
	if got := edgeRoutes([]byte(log), ""); len(got) != 4 {
		t.Fatalf("routes of every client: %v", got)
	}

	var many []string
	for i := range MaxRoutes + 10 {
		many = append(many, fmt.Sprintf(`{"event":"edge.refused","client":"%s","destination":"h%d.example:443"}`, agent, i))
	}
	many = append(many, `{"event":"edge.refused","client":"`+agent+`","destination":"`+strings.Repeat("a", 600)+`"}`)
	if got := edgeRoutes([]byte(strings.Join(many, "\n")), agent); len(got) != MaxRoutes {
		t.Fatalf("%d routes, want at most %d", len(got), MaxRoutes)
	}
}
