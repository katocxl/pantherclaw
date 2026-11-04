// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// brokerKey gives the world's gateway a certificate and a broker key that
// credentials can be sealed to, and returns the key.
func (w *world) brokerKey() ids.UUID {
	w.t.Helper()
	cert, key := ids.NewV7(), ids.NewV7()
	exec(w.t, w.pool, w.org, `INSERT INTO pc.gateway_certs (org_id, id, gateway_id, serial, key_thumbprint, issued_via, not_before, not_after)
		VALUES ($1, $2, $3, $4, $5, 'ENROLL', now(), now() + interval '24 hours')`, w.org, cert, w.gwID, cert[:16], bytes.Repeat([]byte("A"), 43))
	exec(w.t, w.pool, w.org, `INSERT INTO pc.broker_keys (org_id, id, gateway_id, version, public_key, fingerprint, cert_id)
		VALUES ($1, $2, $3, 1, $4, 'sha256:' || encode(sha256($4), 'hex'), $5)`, w.org, key, w.gwID, bytes.Repeat([]byte{7}, 1216), cert)
	return key
}

// credential stores version of a credential of conn, sealed to key, in
// state, and returns its id.
func (w *world) credential(key, conn ids.UUID, version int32, state string) ids.UUID {
	w.t.Helper()
	cred := ids.NewV7()
	exec(w.t, w.pool, w.org, `INSERT INTO pc.credentials (org_id, id, connection_id, version, broker_key_id, sealed, allowed_hosts, header, created_by,
		state, superseded_at, revoked_at, revoked_by)
		VALUES ($1, $2, $3, $4, $5, $6, '{payments.example.test}', 'Authorization', 'test', $7,
		CASE WHEN $7 = 'SUPERSEDED' THEN now() END, CASE WHEN $7 = 'REVOKED' THEN now() END, CASE WHEN $7 = 'REVOKED' THEN 'test' END)`,
		w.org, cred, conn, version, key, bytes.Repeat([]byte{1}, 1200), state)
	return cred
}

// TestHR660_TheServerChecksTheReportedCredential: a receipt names the
// credential the gateway reported only when pc.credentials holds that id
// and version under the permit's connection in the organization, in any
// state. Another version, another connection's or organization's
// credential, an unknown one, or any credential on a permit without a
// connection is refused, and nothing is recorded.
// Covers: F952
func TestHR660_TheServerChecksTheReportedCredential(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.auth.PermitTTL = time.Hour
	w.refundable("ch_1", "ch_2", "ch_3", "ch_4", "ch_5")
	run := w.run(w.grant("500").ID, ids.UUID{})
	key := w.brokerKey()
	versions := []finalize.CredentialUsed{
		{ID: w.credential(key, w.conn, 1, "SUPERSEDED"), Version: 1},
		{ID: w.credential(key, w.conn, 2, "REVOKED"), Version: 2},
		{ID: w.credential(key, w.conn, 3, "ACTIVE"), Version: 3},
	}
	theirs := w.credential(key, w.withConnection("enforce"), 1, "ACTIVE")
	// Another organization, with a connection of the same id as w's and a
	// credential of it.
	other := idrWorldOn(w)
	exec(t, other.pool, other.org, `INSERT INTO pc.connections (org_id, id, name, kind, gateway_id, package, base_url, access_mode,
		default_mode, created_by, updated_by) VALUES ($1, $2, 'payments-same-id', 'http', $3, 'pc.mock-payments', 'https://payments.example.test',
		'none', 'enforce', 'test', 'test')`, other.org, w.conn, other.gwID)
	foreign := other.credential(other.brokerKey(), w.conn, 1, "ACTIVE")

	refused := func(permit ids.UUID, name string, c finalize.CredentialUsed) {
		t.Helper()
		_, err := w.auth.RecordExecution(t.Context(), w.gw, finalize.Execution{
			Permit: permit, Outcome: finalize.Accepted, TargetStatus: 200, DispatchMS: 5, TargetRef: "re_1", Credential: &c,
		})
		if !errors.Is(err, finalize.ErrCredentialNotOfConnection) {
			t.Fatalf("%s: %v", name, err)
		}
		if n := w.count("SELECT count(*) FROM pc.execution_attempts WHERE permit_id = $1", permit); n != 0 {
			t.Fatalf("%s: %d attempts recorded", name, n)
		}
		if st := w.str("SELECT state FROM pc.permits WHERE id = $1", permit); st != "DISPATCHING" {
			t.Fatalf("%s: the permit is %s", name, st)
		}
	}
	r := w.dispatched(run, "ch_1", "10.00")
	for name, c := range map[string]finalize.CredentialUsed{
		"a version that never existed":         {ID: versions[2].ID, Version: 4},
		"an id with another version's number":  {ID: versions[2].ID, Version: 1},
		"another connection's credential":      {ID: theirs, Version: 1},
		"another organization's credential":    {ID: foreign, Version: 1},
		"an unknown credential":                {ID: ids.NewV7(), Version: 1},
		"a credential of a later version's id": {ID: versions[0].ID, Version: 3},
	} {
		refused(r.PermitID, name, c)
	}

	for i, c := range versions {
		if i > 0 {
			r = w.dispatched(run, []string{"", "ch_2", "ch_3"}[i], "10.00")
		}
		receipt, err := w.auth.RecordExecution(ctx, w.gw, finalize.Execution{
			Permit: r.PermitID, Outcome: finalize.Accepted, TargetStatus: 200, DispatchMS: 5, TargetRef: "re_1", Credential: &c,
		})
		if err != nil {
			t.Fatalf("version %d: %v", c.Version, err)
		}
		got, ok := claims(t, receipt)["credential"].(map[string]any)
		if !ok || len(got) != 2 || got["id"] != c.ID.String() || got["version"] != float64(c.Version) {
			t.Fatalf("version %d: credential claim %v", c.Version, got)
		}
	}

	// None reported: no claim.
	r = w.dispatched(run, "ch_4", "10.00")
	receipt, err := w.auth.RecordExecution(ctx, w.gw, finalize.Execution{Permit: r.PermitID, Outcome: finalize.Failed, DispatchMS: 5})
	if err != nil {
		t.Fatal(err)
	}
	if c, ok := claims(t, receipt)["credential"]; ok {
		t.Fatalf("no credential reported, yet the receipt names %v", c)
	}

	// A permit without a connection takes no credential.
	r = w.dispatched(run, "ch_5", "10.00")
	w.db.AdminExec(t, "UPDATE pc.permits SET connection_id = NULL WHERE id = $1", r.PermitID)
	refused(r.PermitID, "a permit without a connection", versions[2])
}

// TestHR660_SweeperReceiptsNameNoCredential: the sweeper's receipt names no
// credential, and a gateway's late report with a credential gets that
// receipt back unchanged; a late report naming a credential that is not the
// connection's is refused as any other.
// Covers: F952
func TestHR660_SweeperReceiptsNameNoCredential(t *testing.T) {
	w := newWorld(t)
	ctx := context.Background()
	w.auth.PermitTTL = time.Hour
	w.refundable("ch_1")
	run := w.run(w.grant("500").ID, ids.UUID{})
	cred := finalize.CredentialUsed{ID: w.credential(w.brokerKey(), w.conn, 1, "ACTIVE"), Version: 1}

	r := w.dispatched(run, "ch_1", "10.00")
	w.db.AdminExec(t, "UPDATE pc.permits SET dispatching_at = now() - interval '1 minute' WHERE id = $1", r.PermitID)
	if _, unknown, err := w.auth.Sweep(ctx, w.org, 30*time.Second); err != nil || unknown != 1 {
		t.Fatalf("sweep: %d unknown, %v", unknown, err)
	}
	swept := w.str("SELECT receipt_jws FROM pc.execution_receipts WHERE permit_id = $1", r.PermitID)
	if c := claims(t, swept); c["recorded_by"] != "sweeper" || c["credential"] != nil {
		t.Fatalf("swept receipt claims %v", c)
	}
	late, err := w.auth.RecordExecution(ctx, w.gw, finalize.Execution{
		Permit: r.PermitID, Outcome: finalize.Accepted, TargetStatus: 200, DispatchMS: -1, TargetRef: "re_late", Credential: &cred,
	})
	if err != nil || late != swept {
		t.Fatalf("a late report: %v, the sweeper's receipt returned %t", err, late == swept)
	}
	wrong := finalize.CredentialUsed{ID: cred.ID, Version: 2}
	if _, err := w.auth.RecordExecution(ctx, w.gw, finalize.Execution{
		Permit: r.PermitID, Outcome: finalize.Accepted, TargetStatus: 200, DispatchMS: -1, TargetRef: "re_late", Credential: &wrong,
	}); !errors.Is(err, finalize.ErrCredentialNotOfConnection) {
		t.Fatalf("a late report of a version that never existed: %v", err)
	}
}
