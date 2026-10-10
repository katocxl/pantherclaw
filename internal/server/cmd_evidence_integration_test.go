// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package server

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestHR194_EvidenceIntegrityResetCommand: `evidence integrity reset`
// changes nothing without --confirm or a reason; with them it sets a FAILED
// org back to OK, audits and notifies in its tenant transaction, and says
// that the ledger is checked again and fails again if it is still broken.
// A second run finds nothing to reset and audits nothing.
func TestHR194_EvidenceIntegrityResetCommand(t *testing.T) {
	d := dbtest.New(t)
	cfgPath := testConfig(t, d, RoleAPI)
	org := ids.New[ids.Org]()
	d.AdminExec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'org')", org)
	d.AdminExec(t, `INSERT INTO pc.evidence_integrity (org_id, state, failure_code, failed_seq, failed_at)
		VALUES ($1, 'FAILED', 'TREE_MISMATCH', 300, now())`, org)
	run := func(args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		code := Run(context.Background(), append([]string{"evidence", "integrity", "reset", "--config", cfgPath}, args...), &out, &errb, noEnv)
		return code, out.String(), errb.String()
	}
	state := func() string {
		var s string
		d.AdminQueryRow(t, "SELECT state FROM pc.evidence_integrity WHERE org_id = $1", []any{org}, &s)
		return s
	}
	count := func(sql string) int {
		var n int
		d.AdminQueryRow(t, sql, []any{org}, &n)
		return n
	}
	audited := func() int {
		return count("SELECT count(*) FROM pc.ledger_entries WHERE org_id = $1 AND kind = 'audit.evidence.integrity_reset'")
	}

	if code, _, errs := run("--org", org.String(), "--reason", "restored from backup"); code == 0 || !strings.Contains(errs, "--confirm") {
		t.Fatalf("without --confirm = %d %s", code, errs)
	}
	if code, _, _ := run("--org", org.String(), "--confirm"); code != 2 {
		t.Fatalf("without a reason = %d, want usage", code)
	}
	if code, _, errs := run("--org", org.String(), "--confirm", "--reason", "two\nlines"); code != 1 || !strings.Contains(errs, "reason") {
		t.Fatalf("with a two-line reason = %d %s", code, errs)
	}
	if code, _, errs := run("--org", ids.New[ids.Org]().String(), "--confirm", "--reason", "typo"); code != 1 ||
		!strings.Contains(errs, "no such organization") {
		t.Fatalf("an unknown org = %d %s", code, errs)
	}
	if state() != "FAILED" || audited() != 0 {
		t.Fatal("a refused reset changed the status or audited")
	}

	code, out, errs := run("--org", org.String(), "--confirm", "--reason", "tile restored from the 2026-10-09 backup")
	if code != 0 || !strings.Contains(out, "it had failed with TREE_MISMATCH at seq 300") || !strings.Contains(out, "FAILS AGAIN") ||
		!strings.Contains(out, "docs/runbooks/evidence-verification.md") {
		t.Fatalf("reset = %d %q %q", code, out, errs)
	}
	if state() != "OK" || audited() != 1 {
		t.Fatalf("after the reset: %s, %d audit entries", state(), audited())
	}
	var actorType, actorID string
	d.AdminQueryRow(t, `SELECT actor_type, actor_id FROM pc.ledger_entries
		WHERE org_id = $1 AND kind = 'audit.evidence.integrity_reset'`, []any{org}, &actorType, &actorID)
	if actorType != "operator" || actorID != "evidence-integrity-reset" {
		t.Fatalf("audited as %s %s", actorType, actorID)
	}
	if n := count("SELECT count(*) FROM pc.notifications WHERE org_id = $1 AND type = 'security.evidence_integrity_reset'"); n != 1 {
		t.Fatalf("%d notifications, want 1", n)
	}

	code, out, errs = run("--org", org.String(), "--confirm", "--reason", "again")
	if code != 0 || !strings.Contains(out, "not FAILED: nothing changed") || audited() != 1 {
		t.Fatalf("second reset = %d %q %q, %d audit entries", code, out, errs, audited())
	}
}
