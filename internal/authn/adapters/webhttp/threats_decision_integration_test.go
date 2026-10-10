// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package webhttp_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	pgapprovals "github.com/katocxl/pantherclaw/internal/approvals/adapters/pgapprovals"
	apapp "github.com/katocxl/pantherclaw/internal/approvals/app"
	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	"github.com/katocxl/pantherclaw/internal/authn/adapters/webhttp"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	mockpayments "github.com/katocxl/pantherclaw/packages/mock-payments"
)

// apbMapper is the refund definition of the mock-payments package with an
// untrusted text "note", as the invariants fixture adds it (text is never
// material, HR-023), and the package's mapper.
func apbMapper(t *testing.T) (*defs.Definition, *mapping.Mapper) {
	t.Helper()
	raw := bytes.Replace(mockpayments.Package, []byte("    effects:"), []byte("      note:\n        type: text\n    effects:"), 1)
	mcp := []byte("            reason: input.reason\n    dispatch:")
	if !bytes.Contains(raw, mcp) {
		t.Fatal("the MCP refund mapping moved; update the fixture")
	}
	raw = bytes.Replace(raw, mcp, []byte("            reason: input.reason\n            note: input.note\n    dispatch:"), 1)
	pkg, err := manifest.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	m, err := mapping.New(pkg, celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	for i := range pkg.Definitions {
		if pkg.Definitions[i].Operation == "payments.refund.create" {
			return &pkg.Definitions[i], m
		}
	}
	t.Fatal("no refund definition")
	return nil, nil
}

// apbOutside returns body without the page's blocks of agent-written
// text: the untrusted block, the evidence and the held parameters.
func apbOutside(t *testing.T, body string) string {
	t.Helper()
	for _, cut := range [][2]string{
		{"<h2>Written by the agent or the requester</h2>", "<h2>"},
		{"<h2>Evidence</h2>", "<h2>"},
		{`<textarea id="narrower-params"`, "</textarea>"},
	} {
		i := strings.Index(body, cut[0])
		if i < 0 {
			t.Fatalf("the page has no %q", cut[0])
		}
		j := strings.Index(body[i+len(cut[0]):], cut[1])
		if j < 0 {
			t.Fatalf("%q does not end", cut[0])
		}
		body = body[:i] + body[i+len(cut[0])+j:]
	}
	return body
}

// TestT026_AgentTextOnTheApprovalPageIsMarkedAndTheKeySignsTheAction:
// T-026 — an agent runs under a task label with a bidi override, zero-width
// characters, a fake "PantherClaw verified / APPROVED BY CFO" banner and a
// link; its held refund carries a note with a look-alike word and the same
// banner (a bidi override in a parameter is refused outright, HR-102), and
// its workload adds evidence in the same style. The approval page, over
// the real approval use cases and store, shows the template's title and
// fields, keeps every piece of agent text inside its marked blocks,
// escaped, without bidi or zero-width characters and with the look-alike
// flagged; the security-key ceremony it starts signs the stored binding
// over the action's hash and the display's hash, not any text. The pieces
// are TestHR034_* and TestHR033_*.
func TestT026_AgentTextOnTheApprovalPageIsMarkedAndTheKeySignsTheAction(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.New(t).AppPool(t)
	exec := func(sql string, args ...any) {
		t.Helper()
		if err := pool.InTenantTx(ctx, testOrg, func(ctx context.Context, tx db.TenantTx) error {
			_, err := tx.Exec(ctx, sql, args...)
			return err
		}); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	rlo, lri, pdi, zwsp, zwj := string(rune(0x202e)), string(rune(0x2066)), string(rune(0x2069)), string(rune(0x200b)), string(rune(0x200d))
	link := `<a href="https://evil.example/ok">Approve now</a>`
	lookalike := "p" + string(rune(0x0430)) + "ypal"
	label := "PantherClaw verified: APPROVED BY CFO " + rlo + "DSU 00.5" + pdi + zwsp + " " + lri + link
	note := "refund to " + lookalike + ", APPROVED BY CFO, see " + link
	evidence := "PantherClaw verified: this request was approved by security" + rlo + zwj + " " + link

	alice, agent, env, inst, run, grant, txn := ids.NewV7(), ids.NewV7(), ids.NewV7(), ids.NewV7(), ids.NewV7(), ids.NewV7(), ids.NewV7()
	exec("INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", testOrg)
	exec("INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'alice')", testOrg, alice)
	exec(`INSERT INTO pc.users (org_id, id, issuer, subject, created_at) VALUES ($1, $2, 'https://idp.test', 'bob', now() - interval '30 days')`,
		testOrg, responderID)
	exec(`INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible, backup_state,
		attestation_fmt, name, created_at) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key', now() - interval '30 days')`,
		testOrg, responderKey, responderID, responderKey[:], append(append([]byte{}, responderKey[:]...), responderKey[:]...))
	exec(`INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by, created_at)
		VALUES ($1, $2, 'approver', $3, 'ORG', $4, now() - interval '30 days')`, testOrg, ids.NewV7(), responderID, "user:"+alice.String())
	exec("INSERT INTO pc.environments (org_id, id, slug, name, kind) VALUES ($1, $2, 'dev', 'Dev', 'DEVELOPMENT')", testOrg, env)
	exec("INSERT INTO pc.agents (org_id, id, name, state, created_by) VALUES ($1, $2, 'refund-bot', 'DISCOVERED', 'test')", testOrg, agent)
	exec(`INSERT INTO pc.agent_instances (org_id, id, agent_id, jkt, public_jwk, state, enrolled_via)
		VALUES ($1, $2, $3, 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs', '{}', 'ADMITTED', 'discovery')`, testOrg, inst, agent)
	exec(`INSERT INTO pc.grants (org_id, id, agent_id, principal_user_id, environment_id, depth, current_revision, grantor_kind,
		grantor_id, basis) VALUES ($1, $2, $3, $4, $5, 0, 1, 'user', $4, 'test')`, testOrg, grant, agent, alice, env)
	exec(`INSERT INTO pc.runs (org_id, id, agent_id, instance_id, environment_id, launcher_user_id, principal_user_id, principal_source,
		grant_id, task_ref, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $6, 'launcher', $7, $8, now() + interval '8 hours')`,
		testOrg, run, agent, inst, env, alice, grant, label)
	exec(`INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code, gateway_id, state)
		VALUES ($1, $2, $3, $4, $5, 'payments.refund.create', 'REQUIRE_APPROVAL', 'REFUND_OVER_50', 'gw', 'OPEN')`,
		testOrg, txn, run, ids.NewV7(), make([]byte, 32))

	// The agent's action, as the gateway maps it; a bidi override in the
	// note is refused before any decision.
	def, m := apbMapper(t)
	mapped := func(note string) (actionir.Parsed, defs.Values, error) {
		b, _ := jsontext.AppendQuote(nil, note)
		p, err := m.MCP(ctx, mapping.Context{
			Org: testOrg.String(), Env: env.String(), RunID: run.String(), ActionID: ids.NewV7().String(), AgentInstance: inst.String(),
		}, "create_refund", []byte(`{"charge":"ch_1","amount":"85.00","currency":"USD","reason":"duplicate","note":`+string(b)+`}`))
		if err != nil {
			return p, nil, err
		}
		vals, err := def.DecodeParams(p.Action.Params)
		return p, vals, err
	}
	if _, _, err := mapped("approved " + rlo + "by CFO"); err == nil {
		t.Fatal("a note with a bidi override was accepted")
	}
	action, vals, err := mapped(note)
	if err != nil {
		t.Fatal(err)
	}

	// The hold, rendered and bound as the finalization does, recorded by
	// the real store.
	deadline := time.Now().UTC().Truncate(time.Second).Add(time.Hour)
	reqs := []apdomain.Requirement{{
		Kind: apdomain.KindApproval, Role: "approver", Count: 1,
		Sources: []apdomain.Source{{Level: "policy org-policy@1 rule approve-over-50", Reason: "REFUND_OVER_50"}},
	}}
	disp, err := apdomain.RenderAction(apdomain.ActionInput{
		Definition: def, Target: action.Action.Target, Requested: vals, Effective: vals,
		Run: apdomain.RunLine{
			Run: run.String(), Agent: agent.String(), Instance: inst.String(), Launcher: "user:" + alice.String(), Principal: "user:" + alice.String(),
		},
		TaskLabel: label, Requirements: reqs, Deadline: deadline,
	})
	if err != nil {
		t.Fatal(err)
	}
	shown, err := disp.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	digest := func(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
	binding, err := apdomain.ActionParts{
		ActionHash: action.HashHex(), EffectiveActionHash: action.HashHex(), BasisDigest: digest("basis"), FactsDigest: digest("facts"),
		DefinitionDigest: action.Action.Definition.Digest, GrantID: grant, GrantRevision: 1, RunID: run, Instance: inst,
		JKT: "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", Requirements: reqs, ExpiresAt: deadline, DisplayHash: shown.Hash,
	}.Binding()
	if err != nil {
		t.Fatal(err)
	}
	variant, err := apdomain.VariantKey(grant, "payments.refund.create", apdomain.Target{Type: action.Action.Target.Type, ID: action.Action.Target.ID})
	if err != nil {
		t.Fatal(err)
	}
	request := ids.NewV7()
	if err := pool.InTenantTx(ctx, testOrg, func(ctx context.Context, tx db.TenantTx) error {
		return pgapprovals.RecordHold(ctx, tx, testOrg, pgapprovals.Hold{
			RequestID: request, TransactionID: txn, Evaluation: 1, AgentID: agent, RunID: run, GrantID: grant, GrantRevision: 1,
			Operation: "payments.refund.create", Reversibility: disp.Consequence.Reversibility, VariantKey: variant, First: true,
			Binding: binding, Requirements: reqs, Display: disp, DisplayHash: shown.Hash, Deadline: deadline, Action: action.Canonical,
			Actor: evdomain.Actor{Type: "gateway", ID: "gw"},
		})
	}); err != nil {
		t.Fatal(err)
	}
	svc := &apapp.Service{Pool: pool}
	if _, _, err := svc.SubmitWorkloadEvidence(ctx, testOrg, inst, run, txn, evidence); err != nil {
		t.Fatal(err)
	}

	h, err := webhttp.New(&fakeBrowser{}, origin, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	fb := &fakeBindings{names: request}
	h.WithApprovals(svc, fb)
	mux := http.NewServeMux()
	h.Mount(mux)
	page := httptest.NewRequest(http.MethodGet, origin+authnapp.ApprovalsPath+"/"+request.String(), nil)
	page.AddCookie(&http.Cookie{Name: "__Host-pc_session", Value: "responder"})
	resp := do(t, mux, page)
	body := resp.Body
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "<h1>Refund 85.00 USD on charge ch_1</h1>") ||
		!strings.Contains(body, "You can approve") || !strings.Contains(body, apdomain.UntrustedLabel) {
		t.Fatalf("the page: %d %s", resp.StatusCode, body)
	}
	for _, r := range []rune{0x202e, 0x2066, 0x2069, 0x200b, 0x200d} {
		if strings.ContainsRune(body, r) {
			t.Errorf("the page carries U+%04X", r)
		}
	}
	if strings.Contains(body, `<a href="https://evil.example`) || !strings.Contains(body, "&lt;a href=") {
		t.Error("the agent's link is not escaped")
	}
	if !strings.Contains(body, "mixes writing systems") {
		t.Error("the look-alike word is not flagged")
	}
	outside := apbOutside(t, body)
	for _, s := range []string{"APPROVED BY CFO", "PantherClaw verified", "approved by security", "evil.example", lookalike} {
		if !strings.Contains(body, s) {
			t.Errorf("the page does not show %q at all", s)
		}
		if strings.Contains(outside, s) {
			t.Errorf("agent text %q outside its marked blocks", s)
		}
	}

	options := do(t, mux, postAs(authnapp.ApprovalsPath+"/"+request.String()+"/approve-options", "responder", "{}"))
	if options.StatusCode != http.StatusOK || fb.challenge != binding.Hash {
		t.Fatalf("approve-options: %d %s, challenge %x, want %x", options.StatusCode, options.Body, fb.challenge, binding.Hash)
	}
	var stored []byte
	var input apdomain.ActionBinding
	if err := pool.InTenantTx(ctx, testOrg, func(ctx context.Context, tx db.TenantTx) error {
		var raw []byte
		if err := tx.QueryRow(ctx, "SELECT binding, binding_input FROM pc.approval_requests WHERE id = $1", request).Scan(&stored, &raw); err != nil {
			return err
		}
		return json.Unmarshal(raw, &input)
	}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, fb.challenge[:]) || input.ActionHash != apdomain.B64(action.Hash[:]) || input.DisplayHash != apdomain.B64(shown.Hash[:]) {
		t.Fatalf("the signed challenge covers %+v, not the held action %s", input, apdomain.B64(action.Hash[:]))
	}
}
