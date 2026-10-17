// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline

import (
	"context"
	"testing"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestM14_PeerCallsAreChecked: a call through an a2a connection asks the
// peer port with the requester's own grant: a reason denies it
// DELEGATION_NOT_ALLOWED, none lets it through, and without the port it
// is CANNOT_AUTHORIZE (fail closed); other kinds are never asked (G0 M14
// D89).
func TestM14_PeerCallsAreChecked(t *testing.T) {
	leaf := gdomain.Grant{ID: gdomain.NewGrantID()}
	var asked []gdomain.GrantID
	run := func(kind string, peer PeerCheck) *state {
		s := &state{
			req: Request{Org: ids.New[ids.Org]()}, ev: &Evaluation{}, conn: &Connection{Kind: kind},
			chain: gdomain.Chain{Grants: []gdomain.Grant{{ID: gdomain.NewGrantID()}, leaf}},
		}
		(&Pipeline{Peer: peer}).peerCheck(context.Background(), s)
		return s
	}
	has := func(s *state, d adomain.Decision, code string) bool {
		for _, it := range s.cl.items {
			if it.effect == d && it.Code == code {
				return true
			}
		}
		return false
	}
	refuse := func(_ context.Context, _ ids.OrgID, _ Connection, g gdomain.Grant) string {
		asked = append(asked, g.ID)
		return "the grant does not allow delegation"
	}
	allow := func(context.Context, ids.OrgID, Connection, gdomain.Grant) string { return "" }
	if s := run("a2a", refuse); !has(s, adomain.Deny, ReasonDelegationNotAllowed) || len(asked) != 1 || asked[0] != leaf.ID {
		t.Fatalf("refused: %+v, asked %v", s.cl.items, asked)
	}
	if s := run("a2a", allow); len(s.cl.items) != 0 {
		t.Fatalf("allowed: %+v", s.cl.items)
	}
	if s := run("a2a", nil); !has(s, adomain.CannotAuthorize, ReasonPeerCheckUnavailable) {
		t.Fatalf("no port: %+v", s.cl.items)
	}
	if s := run("http", refuse); len(s.cl.items) != 0 || len(asked) != 1 {
		t.Fatalf("an http call was asked: %+v", s.cl.items)
	}
	if !dispatches("a2a", &defs.Definition{Dispatch: &defs.Dispatch{A2A: &defs.A2ADispatch{Method: "SendMessage"}}}) ||
		dispatches("a2a", &defs.Definition{Dispatch: &defs.Dispatch{HTTP: &defs.HTTPDispatch{}}}) ||
		!dispatches("postgres", &defs.Definition{Dispatch: &defs.Dispatch{SQL: &defs.SQLDispatch{Operation: "rows"}}}) {
		t.Fatal("a2a and postgres connections serve their own dispatch parts")
	}
}
