// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline

import (
	"context"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
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

// TestM14_A2ADisclosureIsLimited: a disclosure param sent to a peer agent
// at a public destination is checked like one sent over HTTP or MCP: over
// its limits it is DENIED DISCLOSURE_LIMIT, within them it carries the
// disclosure_limits obligation the gateway applies (G0 M14 D96).
func TestM14_A2ADisclosureIsLimited(t *testing.T) {
	def := &defs.Definition{Params: map[string]defs.ParamSpec{"text": {Type: defs.TypeText, Disclosure: true, MaxBytes: 64}}}
	run := func(text string) *state {
		s := &state{
			a: actionir.ActionIR{Channel: string(defs.ChannelA2A)}, ev: &Evaluation{}, def: def,
			conn: &Connection{Kind: "a2a", DestinationClass: "public"},
			vals: defs.Values{"text": {Type: defs.TypeText, Str: text}},
		}
		s.disclosure()
		return s
	}
	s := run("Please refund order 42.")
	if len(s.ev.Obligations) != 1 || s.ev.Obligations[0].Kind != pdomain.DisclosureLimits || s.ev.Obligations[0].Param != "text" ||
		s.ev.Obligations[0].Max != "64" {
		t.Fatalf("within limits: %+v", s.ev.Obligations)
	}
	s = run(strings.Repeat("x", 65))
	denied := false
	for _, it := range s.cl.items {
		denied = denied || (it.effect == adomain.Deny && it.Code == ReasonDisclosureLimit)
	}
	if !denied || len(s.ev.Obligations) != 0 {
		t.Fatalf("over limits: %+v %+v", s.cl.items, s.ev.Obligations)
	}
}

// TestM14_APeerReadIsNotAPeerCall: reading a peer agent's task (an a2a
// read) never consults the peer port, which only decides writes (D111).
func TestM14_APeerReadIsNotAPeerCall(t *testing.T) {
	asked := 0
	s := &state{
		req: Request{Org: ids.New[ids.Org]()}, ev: &Evaluation{}, conn: &Connection{Kind: "a2a"},
		def:   &defs.Definition{Operation: "a2a.task.read", Access: defs.AccessRead},
		chain: gdomain.Chain{Grants: []gdomain.Grant{{ID: gdomain.NewGrantID()}}},
	}
	(&Pipeline{Peer: func(context.Context, ids.OrgID, Connection, gdomain.Grant) string { asked++; return "no" }}).peerCheck(context.Background(), s)
	if asked != 0 || len(s.cl.items) != 0 {
		t.Fatalf("a read asked the port %d times: %+v", asked, s.cl.items)
	}
	s.def.Access = defs.AccessWrite
	(&Pipeline{Peer: func(context.Context, ids.OrgID, Connection, gdomain.Grant) string { asked++; return "no" }}).peerCheck(context.Background(), s)
	if asked != 1 {
		t.Fatal("a write did not ask the port")
	}
}
