// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package server

import (
	"context"
	"strings"
	"testing"
	"time"

	evapp "github.com/katocxl/pantherclaw/internal/evidence/app"
	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/evidence/checkpoints"
	"github.com/katocxl/pantherclaw/internal/evidence/keydocs"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	"github.com/katocxl/pantherclaw/internal/evidence/retention"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestHR198_RemovedReceiptsStillVerifyOffline: refunds authorized through
// an enrolled gateway are chained and checkpointed by a server whose worker
// holds the retention role; once their period has passed the job removes
// the receipt bodies, the replay inputs and the receipt entries' bodies of
// the transaction that is not held, and keeps the held one's. The chain,
// the checkpoints and the daily verification still pass, and an exported
// bundle verifies offline, reporting each removed body as not available
// under its policy revision (F469, F521).
func TestHR198_RemovedReceiptsStillVerifyOffline(t *testing.T) {
	d := dbtest.New(t)
	cfgPath := testConfig(t, d, RoleAll, publicAt(freeAddr(t)), gatewayAt(freeAddr(t)), func(c map[string]any) {
		c["evidence"] = map[string]any{"log_origin": "pc.test"}
		c["database"].(map[string]any)["retention_password_file"] = secretFile(t, t.TempDir(), "retention-pw", d.Retention.Password.Reveal())
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
	count := func(sql string, args ...any) int {
		t.Helper()
		var n int
		if err := p.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			return tx.QueryRow(ctx, sql, args...).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	// sealed waits until a checkpoint covers every chained receipt entry.
	sealed := func() {
		t.Helper()
		for deadline := time.Now().Add(60 * time.Second); ; {
			if count(`SELECT count(*) FROM pc.decision_receipts r
				LEFT JOIN pc.ledger_chain c ON c.org_id = r.org_id AND c.entry_id = r.ledger_entry_id
				WHERE c.seq IS NULL OR c.seq > coalesce((SELECT max(tree_size) FROM pc.checkpoints), 0)`) == 0 {
				return
			}
			if time.Now().After(deadline) {
				t.Fatal("no checkpoint covers the receipts within 60 seconds")
			}
			if _, err := insert.Insert(ctx, checkpoints.CheckpointDispatchArgs{}, nil); err != nil {
				t.Fatal(err)
			}
			time.Sleep(500 * time.Millisecond)
		}
	}
	held := authorizeRefund("10.00")
	free := authorizeRefund("11.00")
	sealed()

	manager := ids.NewV7()
	if err := p.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'records')", org, manager)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	orgScope := td.Scope{Type: td.ScopeOrg, ID: org.UUID()}
	caller := func(id ids.UUID, role td.RoleName) context.Context {
		return tenancy.WithCaller(ctx, tenancy.Caller{Subject: td.Subject{
			Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: id}, Bindings: []td.Binding{{Role: role, Scope: orgScope}},
		}, Credential: tenancy.CredAccessToken})
	}
	admin := &retention.Service{Pool: p}
	if _, err := admin.CreateHold(caller(manager, td.RoleRecordsManager), retention.HoldRequest{
		Scope: retention.ScopeTransaction, ID: &held, Reason: "dispute",
	}); err != nil {
		t.Fatal(err)
	}

	r := &retention.Remover{Pool: d.Pool(t, d.Retention), App: p, Log: pclog.Discard(), Shift: 800 * 24 * time.Hour}
	res, err := r.Run(ctx, org)
	if err != nil {
		t.Fatal(err)
	}
	if res.Total() == 0 {
		t.Fatal("nothing was removed")
	}
	if n := count("SELECT count(*) FROM pc.decision_receipts WHERE transaction_id = $1 AND receipt_jws IS NULL", free); n != 1 {
		t.Fatalf("the free transaction's decision receipt: %d removed", n)
	}
	if n := count("SELECT count(*) FROM pc.decision_receipts WHERE transaction_id = $1 AND receipt_jws IS NULL", held); n != 0 {
		t.Fatal("the held transaction's decision receipt was removed")
	}
	if n := count("SELECT count(*) FROM pc.evaluation_inputs WHERE transaction_id = $1", free); n != 0 {
		t.Fatalf("%d replay inputs of the free transaction kept", n)
	}
	if n := count("SELECT count(*) FROM pc.evaluation_inputs WHERE transaction_id = $1", held); n == 0 {
		t.Fatal("the held transaction's replay inputs were removed")
	}

	// The chain and the checkpoints still verify, and the checkpoint job
	// continues with the job's own audit entries.
	if _, err := ledger.Verify(ctx, p, org); err != nil {
		t.Fatalf("the chain no longer verifies: %v", err)
	}
	before := count("SELECT coalesce(max(tree_size), 0) FROM pc.checkpoints")
	for deadline := time.Now().Add(60 * time.Second); count("SELECT coalesce(max(tree_size), 0) FROM pc.checkpoints") == before; {
		if time.Now().After(deadline) {
			t.Fatal("no checkpoint after the removal")
		}
		if _, err := insert.Insert(ctx, checkpoints.CheckpointDispatchArgs{}, nil); err != nil {
			t.Fatal(err)
		}
		time.Sleep(500 * time.Millisecond)
	}
	if n := count("SELECT count(*) FROM pc.evidence_integrity WHERE state = 'FAILED'"); n != 0 {
		t.Fatal("the removal broke the evidence integrity")
	}

	// The bundle verifies offline; the removed bodies are not available.
	_, doc := getBody(t, base+keydocs.EvidenceKeysPath)
	trust, err := bundle.ParseEvidenceKeys(doc)
	if err != nil {
		t.Fatal(err)
	}
	x, err := evapp.New(p, "pc.test").ExportBundle(caller(ids.NewV7(), td.RoleAuditor), evapp.Selection{Transactions: []ids.UUID{held, free}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := bundle.Decode(x.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	report := bundle.Verify(b, bundle.Options{Trust: trust})
	if report.Failed() {
		t.Fatalf("the bundle fails after the removal:\n%s", report.Text())
	}
	if !passed(report, "receipt.signature") || !passed(report, "entry.link") {
		t.Fatalf("the held transaction's evidence does not verify:\n%s", report.Text())
	}
	if !strings.Contains(report.Text(), "body removed by retention policy receipts r1 on ") {
		t.Fatalf("the removal is not reported:\n%s", report.Text())
	}
	if x.Receipts != 1 || x.Entries != 2 {
		t.Fatalf("export = %d receipts, %d entries; want the held receipt and both entries", x.Receipts, x.Entries)
	}
}
