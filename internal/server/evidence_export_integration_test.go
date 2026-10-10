// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package server

import (
	"context"
	"errors"
	"testing"
	"time"

	evapp "github.com/katocxl/pantherclaw/internal/evidence/app"
	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/evidence/checkpoints"
	"github.com/katocxl/pantherclaw/internal/evidence/keydocs"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// passed reports whether the report has a passed check of name.
func passed(r *bundle.Report, name string) bool {
	for _, c := range r.Checks {
		if c.Name == name && c.Status == bundle.Passed {
			return true
		}
	}
	return false
}

// TestHR196_ABundleExportedFromARunningServerVerifiesOffline: refunds
// authorized through an enrolled gateway get decision receipts, the
// workers chain and checkpoint them, ExportBundle builds a bundle from the
// server's database, and the offline engine of `pclaw verify` passes it
// against the keys of evidence-keys.json, including a checkpoint the
// requester saved earlier. Scopes and other orgs are refused.
func TestHR196_ABundleExportedFromARunningServerVerifiesOffline(t *testing.T) {
	d := dbtest.New(t)
	cfgPath := testConfig(t, d, RoleAll, publicAt(freeAddr(t)), gatewayAt(freeAddr(t)), func(c map[string]any) {
		c["evidence"] = map[string]any{"log_origin": "pc.test"}
	})
	org, enrollFile, keyFile, factsFile := seed(t, cfgPath, "100.00", true)
	base := serve(t, cfgPath)
	ctl := enrollGateway(t, enrollFile)
	wl := seededWorkload(t, base, keyFile)
	refundable(t, base, factsFile)
	p := d.AppPool(t)
	ctx := context.Background()
	insert, err := jobs.NewClient(p, nil, jobs.Config{})
	if err != nil {
		t.Fatal(err)
	}

	authorizeRefund := func(amount string) ids.UUID {
		t.Helper()
		nonce, err := ctl.Authority.GetNonce(ctx, &pantherclawv1.GetNonceRequest{})
		if err != nil {
			t.Fatal(err)
		}
		res, err := authorize(ctl.Authority, refund(t, org, wl, amount), wl.creds(t, nonce.GetNonce()))
		if err != nil || res.GetDecision() != pantherclawv1.Decision_DECISION_ALLOW {
			t.Fatalf("Authorize = %v, %v", res, err)
		}
		id, err := ids.ParseUUID(res.GetTransactionId())
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	// checkpointed waits until a checkpoint covers txn's decision receipt,
	// asking the workers for a dispatch meanwhile, and returns its note.
	checkpointed := func(txn ids.UUID) (uint64, []byte) {
		t.Helper()
		for deadline := time.Now().Add(60 * time.Second); ; {
			var size int64
			var note []byte
			err := p.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
				return tx.QueryRow(ctx, `SELECT k.tree_size, k.note FROM pc.decision_receipts r
					JOIN pc.ledger_chain c ON c.org_id = r.org_id AND c.entry_id = r.ledger_entry_id
					JOIN pc.checkpoints k ON k.org_id = r.org_id AND k.tree_size >= c.seq
					WHERE r.transaction_id = $1 ORDER BY k.tree_size DESC LIMIT 1`, txn).Scan(&size, &note)
			})
			if err == nil {
				return uint64(size), note //nolint:gosec // G115: tree_size > 0
			}
			if !db.IsNoRows(err) {
				t.Fatal(err)
			}
			if time.Now().After(deadline) {
				t.Fatal("no checkpoint covers the transaction within 60 seconds")
			}
			if _, err := insert.Insert(ctx, checkpoints.CheckpointDispatchArgs{}, nil); err != nil {
				t.Fatal(err)
			}
			time.Sleep(500 * time.Millisecond)
		}
	}
	first := authorizeRefund("10.00")
	firstSize, firstNote := checkpointed(first)
	second := authorizeRefund("11.00")
	secondSize, _ := checkpointed(second)
	if secondSize <= firstSize {
		t.Fatalf("checkpoint sizes %d then %d", firstSize, secondSize)
	}

	_, doc := getBody(t, base+keydocs.EvidenceKeysPath)
	trust, err := bundle.ParseEvidenceKeys(doc)
	if err != nil {
		t.Fatal(err)
	}
	caller := func(bs ...td.Binding) context.Context {
		return tenancy.WithCaller(ctx, tenancy.Caller{Subject: td.Subject{
			Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: ids.NewV7()}, Bindings: bs,
		}})
	}
	orgScope := td.Scope{Type: td.ScopeOrg, ID: org.UUID()}
	auditor := caller(td.Binding{Role: td.RoleAuditor, Scope: orgScope})
	svc := evapp.New(p, "pc.test")

	x, err := svc.ExportBundle(auditor, evapp.Selection{Transactions: []ids.UUID{first, second}}, firstSize)
	if err != nil {
		t.Fatal(err)
	}
	b, err := bundle.Decode(x.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	report := bundle.Verify(b, bundle.Options{Trust: trust, Previous: firstNote})
	if report.Failed() {
		t.Fatalf("the exported bundle fails verification:\n%s", report.Text())
	}
	for _, name := range []string{
		"bundle.origin", "checkpoint.signature", "checkpoint.consistency", "witness.previous", "entry.link",
		"entry.inclusion", "receipt.signature", "receipt.ledger",
	} {
		if !passed(report, name) {
			t.Errorf("check %s did not pass:\n%s", name, report.Text())
		}
	}
	if x.Receipts != 2 || x.Entries != 2 || x.CheckpointSize != secondSize {
		t.Fatalf("export = %d receipts, %d entries, checkpoint %d", x.Receipts, x.Entries, x.CheckpointSize)
	}

	// A sequence range covers the org's audit events too: the auditor
	// (audit.read at org scope) exports it; it verifies as well.
	r, err := svc.ExportBundle(auditor, evapp.Selection{From: 1, To: int64(secondSize)}, 0) //nolint:gosec // G115: test sizes
	if err != nil {
		t.Fatal(err)
	}
	rb, err := bundle.Decode(r.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	if rep := bundle.Verify(rb, bundle.Options{Trust: trust}); rep.Failed() || r.Entries != int(secondSize) { //nolint:gosec // G115
		t.Fatalf("range bundle of %d entries:\n%s", r.Entries, rep.Text())
	}

	// Scopes (like run.read) and other orgs.
	developer := caller(td.Binding{Role: td.RoleDeveloper, Scope: orgScope})
	if _, err := svc.ExportBundle(developer, evapp.Selection{Transactions: []ids.UUID{first}}, 0); err != nil {
		t.Fatalf("evidence.read at org scope cannot export a transaction: %v", err)
	}
	if _, err := svc.ExportBundle(developer, evapp.Selection{From: 1, To: 2}, 0); !errors.Is(err, td.ErrPermissionDenied(td.PermAuditRead)) {
		t.Fatalf("a range without audit.read: %v", err)
	}
	otherTeam := caller(td.Binding{Role: td.RoleAgentOwner, Scope: td.Scope{Type: td.ScopeTeam, ID: ids.NewV7()}})
	if _, err := svc.ExportBundle(otherTeam, evapp.Selection{Transactions: []ids.UUID{first}}, 0); !errors.Is(err, td.ErrPermissionDenied(td.PermEvidenceRead)) {
		t.Fatalf("evidence.read in another team: %v", err)
	}
	viewer := caller(td.Binding{Role: td.RoleViewer, Scope: orgScope})
	if _, err := svc.ListCheckpoints(viewer, 10, ""); !errors.Is(err, td.ErrPermissionDenied(td.PermEvidenceRead)) {
		t.Fatalf("checkpoints without evidence.read: %v", err)
	}
	if _, err := svc.ExportBundle(auditor, evapp.Selection{Transactions: []ids.UUID{ids.NewV7()}}, 0); !errors.Is(err, evapp.ErrTxnNotFound) {
		t.Fatalf("an unknown transaction: %v", err)
	}
	stranger := tenancy.WithCaller(ctx, tenancy.Caller{Subject: td.Subject{
		Org: ids.New[ids.Org](), Principal: td.PrincipalRef{Kind: td.KindUser, ID: ids.NewV7()},
		Bindings: []td.Binding{{Role: td.RoleAuditor}},
	}})
	if _, err := svc.ExportBundle(stranger, evapp.Selection{Transactions: []ids.UUID{first}}, 0); !errors.Is(err, evapp.ErrTxnNotFound) {
		t.Fatalf("another org's transaction: %v (want not found, T-037)", err)
	}

	// The proofs the RPCs serve agree with the bundle's checkpoint.
	page, err := svc.ListCheckpoints(auditor, 1, "")
	if err != nil || len(page.Items) != 1 || page.Items[0].Size != secondSize || page.Next == "" || page.Origin != "pc.test/org/"+org.String() {
		t.Fatalf("ListCheckpoints = %+v, %v", page, err)
	}
	if _, err := svc.GetConsistencyProof(auditor, firstSize, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GetInclusionProof(auditor, 1, firstSize); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GetInclusionProof(auditor, int64(secondSize), firstSize); !errors.Is(err, evapp.ErrNotInCheckpoint) { //nolint:gosec // G115
		t.Fatalf("an entry after the checkpoint: %v", err)
	}
}
