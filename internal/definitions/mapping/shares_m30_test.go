// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package mapping

import (
	"context"
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
)

// TestHR707_MapperFillsSharesFromExtractors: the gateway mapper fills
// Shares from the package's extractors only: a public visibility and a
// transfer name their destination, a private visibility shares to no one
// (G0 M30 D934).
//
// Covers: HR-707
func TestHR707_MapperFillsSharesFromExtractors(t *testing.T) {
	m := githubMapper(t)
	ctx := context.Background()
	pub := actionir.Destination{Kind: actionir.SharePublic, ID: actionir.ShareIDPublic}
	cases := []struct {
		tool, args string
		want       []actionir.Destination
	}{
		{"update_repository_visibility", `{"owner":"acme","repo":"payments","visibility":"public"}`, []actionir.Destination{pub}},
		{"update_repository_visibility", `{"owner":"acme","repo":"payments","visibility":"private"}`, nil},
		{"transfer_repository", `{"owner":"acme","repo":"payments","new_owner":"evil-org"}`, []actionir.Destination{{Kind: actionir.ShareGitHubOrg, ID: "evil-org"}}},
	}
	for _, c := range cases {
		a, err := m.MCP(ctx, tc, c.tool, []byte(c.args))
		if err != nil {
			t.Fatalf("%s %s: %v", c.tool, c.args, err)
		}
		if !slices.Equal(a.Action.Shares, c.want) {
			t.Errorf("%s %s: shares %+v, want %+v", c.tool, c.args, a.Action.Shares, c.want)
		}
	}
	// An agent cannot name its own shares: an extra argument is refused by
	// the closed input schema, so nothing it sends lands in Shares.
	if _, err := m.MCP(ctx, tc, "update_repository_visibility", []byte(`{"owner":"acme","repo":"payments","visibility":"private","shares":[]}`)); err == nil {
		t.Fatal("an agent-supplied shares field was accepted")
	}
}
