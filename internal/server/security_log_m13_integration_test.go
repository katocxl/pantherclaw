// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package server

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

func TestHR383_SecurityLogCLIExportsExclusivelyAndAuditsExplicitACK(t *testing.T) {
	d := dbtest.New(t)
	cfg := testConfig(t, d, RoleAPI)
	p := d.AppPool(t)
	ctx := context.Background()
	org := ids.New[ids.Org]()
	d.AdminExec(t, "INSERT INTO pc.orgs(id,name) VALUES($1,'security-cli')", org)
	body, err := domain.CanonicalBody(map[string]any{"outcome": "success", "object": map[string]string{"type": "api_key", "id": ids.NewV7().String()}})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := ledger.Append(ctx, tx, "audit.access.api_key_revoked", domain.Actor{Type: "user", ID: ids.NewV7().String()}, body)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// The chainer takes only entries below the cluster-wide xmin, so a
	// transaction open in a concurrently running test package can hold the
	// entry back briefly: chain until it is chained.
	chained := 0
	for deadline := time.Now().Add(time.Minute); chained < 1; time.Sleep(100 * time.Millisecond) {
		n, err := ledger.ChainAll(ctx, p, org, 500)
		if err != nil {
			t.Fatal(err)
		}
		chained += n
		if chained < 1 && time.Now().After(deadline) {
			t.Fatal("the entry was not chained within a minute")
		}
	}
	if chained != 1 {
		t.Fatalf("chain=%d", chained)
	}
	run := func(args ...string) (int, string, string) {
		t.Helper()
		var out, errs bytes.Buffer
		code := Run(ctx, append(append([]string{"security-log"}, args...), "--org", org.String(), "--config", cfg), &out, &errs, noEnv)
		return code, out.String(), errs.String()
	}
	path := filepath.Join(t.TempDir(), "security.ndjson")
	if code, out, errs := run("export", "--out", path); code != 0 || !strings.Contains(out, "no events acknowledged") {
		t.Fatalf("export=%d %s %s", code, out, errs)
	}
	before, err := os.ReadFile(path)
	if err != nil || !bytes.Contains(before, []byte(`"kind": "access.api_key_revoked"`)) && !bytes.Contains(before, []byte(`"kind":"access.api_key_revoked"`)) {
		t.Fatalf("export contents: %s %v", before, err)
	}
	if code, _, _ := run("export", "--out", path); code != 1 {
		t.Fatal("export overwrote an existing file")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed exclusive export changed the file")
	}
	if code, _, _ := run("ack", "--through", "1"); code != 1 {
		t.Fatal("ACK without confirmation succeeded")
	}
	if code, _, _ := run("ack", "--through", "2", "--confirm"); code != 1 {
		t.Fatal("ACK of missing security sequence succeeded")
	}
	var count int
	d.AdminQueryRow(t, "SELECT count(*) FROM pc.security_event_outbox WHERE org_id=$1 AND acknowledged_at IS NOT NULL", []any{org}, &count)
	if count != 0 {
		t.Fatal("export or refused ACK changed acknowledgement state")
	}
	if code, out, errs := run("ack", "--through", "1", "--confirm"); code != 0 {
		t.Fatalf("ACK=%d %s %s", code, out, errs)
	}
	d.AdminQueryRow(t, "SELECT count(*) FROM pc.security_event_outbox WHERE org_id=$1 AND acknowledged_at IS NOT NULL", []any{org}, &count)
	if count != 1 {
		t.Fatal("explicit ACK did not retain and acknowledge the row")
	}
	d.AdminQueryRow(t, "SELECT count(*) FROM pc.ledger_entries WHERE org_id=$1 AND kind='audit.security_log.acknowledged' AND actor_type='operator'", []any{org}, &count)
	if count != 1 {
		t.Fatalf("operator ACK audits=%d", count)
	}
}
