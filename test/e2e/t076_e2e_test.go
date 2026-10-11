// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"fmt"
	"slices"
	"testing"
	"time"

	evapp "github.com/katocxl/pantherclaw/internal/evidence/app"
	"github.com/katocxl/pantherclaw/internal/evidence/capture"
	"github.com/katocxl/pantherclaw/internal/evidence/pack"
	"github.com/katocxl/pantherclaw/internal/evidence/packbuild"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	txapp "github.com/katocxl/pantherclaw/internal/transactions/app"
)

// boundAs is a person of the org bound to role in the database too (a
// pack's builder reads its creator's bindings when it runs).
func (s *stack) boundAs(t *testing.T, name string, role td.RoleName, cred tapp.Credential) context.Context {
	t.Helper()
	id := ids.NewV7()
	s.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)", s.org, id, name)
	s.exec(t, `INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by) VALUES ($1, $2, $3, $4, 'ORG', 'test')`,
		s.org, ids.NewV7(), string(role), id)
	return tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
		Org: s.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: id},
		Bindings: []td.Binding{{Role: role, Scope: td.Scope{Type: td.ScopeOrg, ID: s.org.UUID()}}},
	}, Credential: cred})
}

// TestT076_ACaptureTakenAtTheGatewayLeavesOnlyThroughAnAuditedRead is
// T-076's misuse through the real gateway: a Records Manager's capture
// profile (audited under their name) reaches the gateway, which captures a
// refund's request and response. The captured bodies never appear in the
// explorer's answer, in the server's logs, or in an evidence pack: not by
// default, and not for a creator without evidence.read_restricted who asks
// (the gap says why). Whoever configured capture, an Org Admin, a service
// and an API key cannot read them, and a read without a reason is refused;
// none of these leaves a read record. An Auditor's read with a reason
// returns what the gateway sent and is audited (HR-199, T-043).
func TestT076_ACaptureTakenAtTheGatewayLeavesOnlyThroughAnAuditedRead(t *testing.T) {
	s := start(t, options{budget: "1000.00"})
	p := s.proof(t)
	ctx := context.Background()
	svc := &capture.Service{Pool: s.pool, Env: pccrypto.NewEnvelope(keystore.NewCurrentCache(keystore.NewDEKStore(s.pool, p.kp), time.Minute, clock.System{}))}
	manager := s.boundAs(t, "records-manager", td.RoleRecordsManager, tapp.CredAccessToken)
	if _, err := svc.CreateProfile(manager, capture.ProfileRequest{
		Purpose: "dispute investigation", Connections: []ids.UUID{s.conn}, Operations: []string{"payments.refund.create"},
		Request: true, Response: true, ByteCap: 4096, RetentionDays: 7, ExpiresInDays: 30,
	}); err != nil {
		t.Fatal(err)
	}
	if n := s.row(t, "SELECT count(*)::text FROM pc.ledger_entries WHERE kind = 'audit.evidence.capture_profile_created'"); n != "1" {
		t.Fatalf("%s profile creations audited", n)
	}
	s.waitConfig(t, s.configVersion(t, s.gatewayID(t)))

	txn := s.refunded(t, "30.00", "CONFIRMED")
	if n := s.row(t, "SELECT count(*)::text FROM pc.payload_captures WHERE transaction_id = $1", txn); n != "2" {
		t.Fatalf("%s captures kept, want the request and the response", n)
	}

	// What could leak, collected before anyone reads a capture.
	auditor := s.boundAs(t, "capture-auditor", td.RoleAuditor, tapp.CredAccessToken)
	ev, err := (&txapp.Explorer{Pool: s.pool}).TransactionEvidence(auditor, txn)
	if err != nil {
		t.Fatal(err)
	}
	explorer, err := json.Marshal(ev)
	if err != nil {
		explorer = fmt.Appendf(nil, "%+v", ev)
	}
	var queued []ids.UUID
	packs := evapp.New(s.pool, p.origin).WithPacks(func(_ context.Context, _ db.TenantTx, _ ids.OrgID, id ids.UUID) error {
		queued = append(queued, id)
		return nil
	}, teamEdition{})
	builder := &packbuild.Service{
		Pool: s.pool, Keys: p.reg, LogOrigin: p.origin, Explorer: &txapp.Explorer{Pool: s.pool}, Bundles: evapp.New(s.pool, p.origin),
		Log: pclog.Discard(),
	}
	packOf := func(who context.Context, captures bool) (map[string][]byte, *pack.Manifest) {
		t.Helper()
		pk, err := packs.CreateEvidencePack(who, evapp.PackRequest{Kind: pack.ScopeTransactions, Transactions: []ids.UUID{txn},
			Include: pack.Include{Receipts: true, Captures: captures}})
		if err != nil {
			t.Fatal(err)
		}
		if err := builder.Build(ctx, s.org, pk.ID); err != nil {
			t.Fatal(err)
		}
		d, err := packs.DownloadEvidencePack(who, pk.ID)
		if err != nil {
			t.Fatal(err)
		}
		files, err := pack.Read(d.Content)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := pack.ParseJWS(string(files[pack.ManifestPath]))
		if err != nil {
			t.Fatal(err)
		}
		m, err := pack.DecodeManifest(signed.Payload)
		if err != nil {
			t.Fatal(err)
		}
		return files, m
	}
	byDefault, m := packOf(auditor, false)
	if slices.ContainsFunc(m.Gaps, func(g pack.Gap) bool { return g.Subject == "captures" }) {
		t.Fatalf("a pack that did not ask for captures says something about them: %+v", m.Gaps)
	}
	security := s.boundAs(t, "security-admin", td.RoleSecurityAdmin, tapp.CredAccessToken)
	asked, m := packOf(security, true)
	if !slices.ContainsFunc(m.Gaps, func(g pack.Gap) bool { return g.Subject == "captures" && g.Reason == pack.GapOutsidePermission }) {
		t.Fatalf("a pack asking for captures without evidence.read_restricted: gaps %+v", m.Gaps)
	}

	// Nobody but a person holding evidence.read_restricted, with a reason,
	// reads a capture.
	for name, who := range map[string]context.Context{
		"whoever configured capture": manager,
		"an org admin":               s.boundAs(t, "org-admin", td.RoleOrgAdmin, tapp.CredAccessToken),
		"an auditor's api key":       s.boundAs(t, "keyed-auditor", td.RoleAuditor, tapp.CredAPIKey),
		"a service account": tapp.WithCaller(ctx, tapp.Caller{Subject: td.Subject{
			Org: s.org, Principal: td.PrincipalRef{Kind: td.KindServiceAccount, ID: ids.NewV7()},
			Bindings: []td.Binding{{Role: td.RoleAuditor, Scope: td.Scope{Type: td.ScopeOrg, ID: s.org.UUID()}}},
		}, Credential: tapp.CredAccessToken}),
	} {
		if _, err := svc.ReadCapture(who, txn, capture.Request, "curious"); pcerr.CodeOf(err) != pcerr.PermissionDenied {
			t.Errorf("%s read a capture: %v", name, err)
		}
	}
	if _, err := svc.ReadCapture(auditor, txn, capture.Request, ""); err == nil {
		t.Fatal("a capture was read without a reason")
	}
	if n := s.row(t, "SELECT count(*)::text FROM pc.ledger_entries WHERE kind = 'audit.evidence.payload_read'"); n != "0" {
		t.Fatalf("%s reads recorded before any was allowed", n)
	}
	var sent [][]byte
	for _, dir := range []capture.Direction{capture.Request, capture.Response} {
		r, err := svc.ReadCapture(auditor, txn, dir, "dispute 2026-117")
		if err != nil || len(r.Content) == 0 {
			t.Fatalf("the auditor's read of the %s: %+v, %v", dir, r, err)
		}
		sent = append(sent, r.Content)
	}
	if !bytes.Contains(sent[0], []byte(`"30.00"`)) {
		t.Fatalf("the captured request %s is not the refund the gateway sent", sent[0])
	}
	if n := s.row(t, "SELECT count(*)::text FROM pc.ledger_entries WHERE kind = 'audit.evidence.payload_read'"); n != "2" {
		t.Fatalf("%s reads audited, want 2", n)
	}

	leaks := map[string][]byte{"the explorer": explorer, "the server's logs": []byte(s.logs.String())}
	for name, files := range map[string]map[string][]byte{"a default pack": byDefault, "the security admin's pack": asked} {
		for path, data := range files {
			leaks[name+" "+path] = data
		}
	}
	for where, data := range leaks {
		for _, content := range sent {
			if bytes.Contains(data, content) || bytes.Contains(data, []byte(base64.StdEncoding.EncodeToString(content))) {
				t.Errorf("%s holds a captured body", where)
			}
		}
	}
	if s.simCalls.Load() != 1 || len(s.sim.Refunds()) != 1 {
		t.Fatalf("%d dispatches for one refund", s.simCalls.Load())
	}
}
