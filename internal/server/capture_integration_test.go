// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package server

import (
	"context"
	"encoding/json/v2"
	"os"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/capture"
	"github.com/katocxl/pantherclaw/internal/evidence/pack"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestHR199_CapturesTravelFromTheGatewayToAnAuditedRead: a Records
// Manager's capture profile reaches the enrolled gateway's configuration;
// the bodies the gateway reports with RecordExecution are kept sealed by
// the running server; an Auditor reads one with a reason, and the read is
// audited. A body under no profile is dropped without failing the outcome.
func TestHR199_CapturesTravelFromTheGatewayToAnAuditedRead(t *testing.T) {
	d := dbtest.New(t)
	cfgPath := testConfig(t, d, RoleAll, publicAt(freeAddr(t)), gatewayAt(freeAddr(t)))
	org, enrollFile, keyFile, factsFile := seed(t, cfgPath, "100.00", true)
	base := serve(t, cfgPath)
	ctl := enrollGateway(t, enrollFile)
	wl := seededWorkload(t, base, keyFile)
	refundable(t, base, factsFile)
	p := d.AppPool(t)
	ctx := context.Background()

	// The server's key-encryption key opens what the server sealed.
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		KEKFiles []string `json:"kek_files"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	kp, err := keys.NewFileProvider(cfg.KEKFiles)
	if err != nil {
		t.Fatal(err)
	}
	svc := &capture.Service{Pool: p, Env: pccrypto.NewEnvelope(keystore.NewCurrentCache(keystore.NewDEKStore(p, kp), time.Minute, clock.System{}))}

	var conn ids.UUID
	manager, auditor := ids.NewV7(), ids.NewV7()
	if err := p.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		if err := tx.QueryRow(ctx, "SELECT id FROM pc.connections LIMIT 1").Scan(&conn); err != nil {
			return err
		}
		for _, u := range []ids.UUID{manager, auditor} {
			if _, err := tx.Exec(ctx, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)",
				org, u, u.String()); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	as := func(u ids.UUID, role td.RoleName) context.Context {
		return tenancy.WithCaller(ctx, tenancy.Caller{Subject: td.Subject{
			Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: u},
			Bindings: []td.Binding{{Role: role, Scope: td.Scope{Type: td.ScopeOrg, ID: org.UUID()}}},
		}, Credential: tenancy.CredAccessToken})
	}
	profile, err := svc.CreateProfile(as(manager, td.RoleRecordsManager), capture.ProfileRequest{
		Purpose: "dispute investigation", Connections: []ids.UUID{conn}, Operations: []string{"payments.refund.create"},
		Request: true, Response: true, ByteCap: 4096, RetentionDays: 7, ExpiresInDays: 30,
	})
	if err != nil {
		t.Fatal(err)
	}
	gc, err := ctl.Gateway.GetConfiguration(ctx, &pantherclawv1.GetConfigurationRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if ps := gc.GetCaptureProfiles(); len(ps) != 1 || ps[0].GetId() != profile.ID.String() || ps[0].GetConnectionIds()[0] != conn.String() ||
		ps[0].GetByteCap() != 4096 || !ps[0].GetRequest() || !ps[0].GetResponse() {
		t.Fatalf("the gateway's capture profiles = %v", ps)
	}

	nonce, err := ctl.Authority.GetNonce(ctx, &pantherclawv1.GetNonceRequest{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := authorize(ctl.Authority, refund(t, org, wl, "10.00"), wl.creds(t, nonce.GetNonce()))
	if err != nil || res.GetDecision() != pantherclawv1.Decision_DECISION_ALLOW {
		t.Fatalf("Authorize = %v, %v", res, err)
	}
	if _, err := ctl.Authority.BeginDispatch(ctx, &pantherclawv1.BeginDispatchRequest{PermitId: res.GetPermitId(), Epoch: res.GetEpoch()}); err != nil {
		t.Fatal(err)
	}
	const sent, answer = `{"amount":"10.00","charge":"ch_1","currency":"USD"}`, `{"id":"re_9","status":"succeeded"}`
	rec, err := ctl.Authority.RecordExecution(ctx, &pantherclawv1.RecordExecutionRequest{
		PermitId: res.GetPermitId(), Outcome: pantherclawv1.Outcome_OUTCOME_ACCEPTED, TargetStatus: 200,
		Captures: []*pantherclawv1.PayloadCapture{
			{ProfileId: profile.ID.String(), Direction: pantherclawv1.CaptureDirection_CAPTURE_DIRECTION_REQUEST, Content: []byte(sent), Size: int64(len(sent))},
			{ProfileId: ids.NewV7().String(), Direction: pantherclawv1.CaptureDirection_CAPTURE_DIRECTION_RESPONSE, Content: []byte(answer), Size: int64(len(answer))},
		},
	})
	if err != nil || rec.GetReceipt() == "" {
		t.Fatalf("RecordExecution = %v, %v", rec, err)
	}
	txn, err := ids.ParseUUID(res.GetTransactionId())
	if err != nil {
		t.Fatal(err)
	}
	var kept int
	if err := p.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT count(*) FROM pc.payload_captures WHERE transaction_id = $1", txn).Scan(&kept)
	}); err != nil || kept != 1 {
		t.Fatalf("%d captures kept (%v), want the request only", kept, err)
	}
	r, err := svc.ReadCapture(as(auditor, td.RoleAuditor), txn, capture.Request, "dispute 2026-117")
	if err != nil || string(r.Content) != sent {
		t.Fatalf("read = %+v, %v", r, err)
	}
	if _, err := svc.ReadCapture(as(manager, td.RoleRecordsManager), txn, capture.Request, "curious"); err == nil {
		t.Fatal("whoever configures capture read it")
	}

	// An evidence pack's captures (G0 M7 deviation 4) go through the same
	// audited read, as the pack's creator, naming the pack: the request
	// that was kept, never the response that was dropped.
	reads := func(reason string) int {
		var n int
		if err := p.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.evidence.payload_read'
				AND convert_from(body, 'UTF8')::jsonb #>> '{details,reason}' = $1
				AND convert_from(body, 'UTF8')::jsonb #>> '{details,transaction}' = $2`, reason, txn.String()).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	src, packID := capture.PackSource{Service: svc}, ids.NewV7()
	if _, err := src.Captures(as(manager, td.RoleRecordsManager), org, packID, txn); pcerr.CodeOf(err) != pcerr.PermissionDenied {
		t.Fatalf("a pack by whoever configures capture: %v", err)
	}
	if _, err := src.Captures(as(auditor, td.RoleAuditor), ids.New[ids.Org](), packID, txn); pcerr.CodeOf(err) != pcerr.PermissionDenied {
		t.Fatalf("a pack of another org: %v", err)
	}
	if n := reads(capture.PackReason(packID)); n != 0 {
		t.Fatalf("%d pack reads audited before one was allowed", n)
	}
	files, err := src.Captures(as(auditor, td.RoleAuditor), org, packID, txn)
	if err != nil || len(files) != 1 || files[0].Path != "captures/"+txn.String()+"/request.bin" || files[0].Kind != pack.KindCapture ||
		string(files[0].Data) != sent {
		t.Fatalf("the pack's captures = %+v, %v", files, err)
	}
	if n := reads(capture.PackReason(packID)); n != 1 {
		t.Fatalf("%d pack reads audited, want the request's", n)
	}
}
