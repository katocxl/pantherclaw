// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package securityevent_test

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	"github.com/katocxl/pantherclaw/internal/evidence/securityevent"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

func appendRevocation(t *testing.T, p *db.Pool, org ids.OrgID, object string) {
	t.Helper()
	body, err := domain.CanonicalBody(map[string]any{"outcome": "success", "object": securityevent.Object{Type: "api_key", ID: object}, "details": map[string]string{"reason": "must never leave database", "payload": "secret-body"}})
	if err != nil {
		t.Fatal(err)
	}
	err = p.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := ledger.Append(ctx, tx, "audit.access.api_key_revoked", domain.Actor{Type: "user", ID: ids.NewV7().String()}, body)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

// The process may die immediately after chain commit. The outbox must
// already contain the filtered record even though no log call has run.
func TestHR383_CommitGapRetriedWithoutRemoteAcknowledgement(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	ctx := context.Background()
	org, other := ids.New[ids.Org](), ids.New[ids.Org]()
	d.AdminExec(t, `INSERT INTO pc.orgs(id,name) VALUES($1,'outbox'),($2,'other')`, org, other)
	appendRevocation(t, p, org, ids.NewV7().String())
	if n, err := ledger.ChainAll(ctx, p, org, 500); err != nil || n != 1 {
		t.Fatalf("chain=%d %v", n, err)
	}
	var payload string
	var attempts, acked int
	d.AdminQueryRow(t, `SELECT payload::text,attempts,(acknowledged_at IS NOT NULL)::integer FROM pc.security_event_outbox WHERE org_id=$1`, []any{org}, &payload, &attempts, &acked)
	if attempts != 0 || acked != 0 || strings.Contains(payload, "must never") || strings.Contains(payload, "secret-body") {
		t.Fatalf("invalid durable projection: attempts=%d ack=%d payload=%s", attempts, acked, payload)
	}
	first, err := securityevent.Attempt(ctx, p, org)
	if err != nil || len(first) != 1 {
		t.Fatalf("attempt=%v %v", first, err)
	}
	// Simulate crash after attempt commit, before calling Emit. A new
	// worker sees the stored retry gate; no duplicate immediate burst.
	again, err := securityevent.Attempt(ctx, p, org)
	if err != nil || len(again) != 0 {
		t.Fatalf("immediate retry=%v %v", again, err)
	}
	d.AdminExec(t, `UPDATE pc.security_event_outbox SET last_emitted_at=now()-interval '6 minutes' WHERE org_id=$1`, org)
	retry, err := securityevent.Attempt(ctx, p, org)
	if err != nil || len(retry) != 1 || retry[0].LedgerSeq != first[0].LedgerSeq || retry[0].Org != org {
		t.Fatalf("retry=%v %v", retry, err)
	}
	var output bytes.Buffer
	n, last, err := securityevent.Export(ctx, p, org, 0, 500, &output)
	if err != nil || n != 1 || last != 1 {
		t.Fatalf("export=%d %d %v", n, last, err)
	}
	var decoded securityevent.Event
	if err := json.Unmarshal(bytes.TrimSpace(output.Bytes()), &decoded); err != nil || decoded.Kind != "access.api_key_revoked" {
		t.Fatalf("export contents: %v", err)
	}
	// Export and local attempts never imply durable external delivery.
	d.AdminQueryRow(t, `SELECT attempts,(acknowledged_at IS NOT NULL)::integer FROM pc.security_event_outbox WHERE org_id=$1`, []any{org}, &attempts, &acked)
	if attempts != 2 || acked != 0 {
		t.Fatalf("attempts=%d ack=%d", attempts, acked)
	}
	err = p.InTenantTx(ctx, other, func(ctx context.Context, tx db.TenantTx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM pc.security_event_outbox WHERE org_id=$1`, org).Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			t.Error("cross-tenant outbox read")
		}
		if _, err := securityevent.AcknowledgeIn(ctx, tx, 1); err == nil {
			t.Error("cross-tenant acknowledgement succeeded")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	err = p.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		if _, err := securityevent.AcknowledgeIn(ctx, tx, 2); err == nil {
			t.Error("nonexistent through accepted")
		}
		n, err := securityevent.AcknowledgeIn(ctx, tx, 1)
		if n != 1 {
			t.Errorf("acked rows=%d", n)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	remaining, err := securityevent.Attempt(ctx, p, org)
	if err != nil || len(remaining) != 0 {
		t.Fatalf("acked retried=%v %v", remaining, err)
	}
	d.AdminQueryRow(t, `SELECT count(*) FROM pc.security_event_outbox WHERE org_id=$1`, []any{org}, &n)
	if n != 1 {
		t.Fatal("ack deleted durable row")
	}
}

func TestHR383_InvalidProjectionRollsBackEntireChainBatch(t *testing.T) {
	d := dbtest.New(t)
	p := d.AppPool(t)
	ctx := context.Background()
	org := ids.New[ids.Org]()
	d.AdminExec(t, `INSERT INTO pc.orgs(id,name) VALUES($1,'outbox')`, org)
	appendRevocation(t, p, org, ids.NewV7().String())
	appendRevocation(t, p, org, "malformed")
	if _, err := ledger.ChainAll(ctx, p, org, 500); err == nil {
		t.Fatal("invalid projection chained")
	}
	for _, table := range []string{"ledger_chain", "security_event_outbox"} {
		var n int
		d.AdminQueryRow(t, `SELECT count(*) FROM pc.`+table+` WHERE org_id=$1`, []any{org}, &n)
		if n != 0 {
			t.Errorf("%s partially committed %d rows", table, n)
		}
	}
}

// Intent creation, chaining, local emission and export are all insufficient
// to erase data. Only the exact externally verified ACK unlocks the phase.
func TestHR383_DeletionIntentWaitsForExactExternalCopyAcknowledgement(t *testing.T) {
	for _, kind := range []string{"org.deletion_started", "account.deletion_started"} {
		t.Run(kind, func(t *testing.T) {
			d := dbtest.New(t)
			p := d.AppPool(t)
			ctx := context.Background()
			target, request := ids.NewV7(), ids.NewV7()
			digest := strings.Repeat("a", 64)
			check := func(want bool) {
				t.Helper()
				got, err := securityevent.IntentAcknowledged(ctx, p, kind, target, digest)
				if err != nil || got != want {
					t.Fatalf("intent ready=%v want %v: %v", got, want, err)
				}
			}
			check(false)
			_, typ, _ := securityevent.Rule(kind)
			details := map[string]string{"journal_digest": digest}
			if kind == "org.deletion_started" {
				details["request_id"] = request.String()
			}
			body, err := domain.CanonicalBody(map[string]any{"outcome": "success", "object": securityevent.Object{Type: typ, ID: target.String()}, "details": details})
			if err != nil {
				t.Fatal(err)
			}
			err = p.InTenantTx(ctx, ids.PlatformOrg, func(ctx context.Context, tx db.TenantTx) error {
				_, err := ledger.Append(ctx, tx, "audit."+kind, domain.Actor{Type: "system", ID: "deletion"}, body)
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
			check(false) // crash/retry before the asynchronous chainer
			if _, err := ledger.ChainAll(ctx, p, ids.PlatformOrg, 500); err != nil {
				t.Fatal(err)
			}
			check(false)
			if _, err := securityevent.Attempt(ctx, p, ids.PlatformOrg); err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			_, through, err := securityevent.Export(ctx, p, ids.PlatformOrg, 0, 500, &output)
			if err != nil || through < 1 {
				t.Fatalf("export: through=%d %v", through, err)
			}
			check(false) // retry after a local attempt/export is still held
			err = p.InTenantTx(ctx, ids.PlatformOrg, func(ctx context.Context, tx db.TenantTx) error {
				_, err := securityevent.AcknowledgeIn(ctx, tx, through)
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
			check(true)
			check(true) // an acknowledged retry is stable
			for _, wrong := range []struct {
				kind   string
				target ids.UUID
				digest string
			}{{kind, ids.NewV7(), digest}, {kind, target, strings.Repeat("b", 64)}} {
				if got, err := securityevent.IntentAcknowledged(ctx, p, wrong.kind, wrong.target, wrong.digest); err != nil || got {
					t.Fatalf("another intent unlocked deletion: ready=%v err=%v", got, err)
				}
			}
		})
	}
}
