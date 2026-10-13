// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
)

// These tests check the schema's second line of defense for G0 M8 track P
// slice P1 (migration 00083): the application enforces the same rules
// first. Names are prefixed m8p1 so that they never collide with other
// milestones' schema tests in this package.

const m8p1Consequence = `INSERT INTO pc.decision_consequences (org_id, transaction_id, evaluation, position, rule_id, operation, target_type,
	target_id, environments, state, unknown, facts_digest)
	VALUES ($1, $2, $3, $4, 'merge-triggers-deployment', 'github.deployment.trigger', 'github.repository', 'acme/payments', $5, $6, $7,
	'sha256:` + "0000000000000000000000000000000000000000000000000000000000000000" + `')`

// TestHR206_DecisionConsequencesAreEvidence: pc_app records what a
// consequence rule said with the evaluation's decision receipt, never
// without one; an UNKNOWN consequence says why and only a PREDICTED one
// names environments; rows are never changed or deleted, and auditors read
// them.
func TestHR206_DecisionConsequencesAreEvidence(t *testing.T) {
	d := dbtest.New(t)
	f := m7rFixture(t, d)
	none := []string{}
	f.mustExec(t, m8p1Consequence, f.org, f.txn, 1, 0, []string{"production"}, "PREDICTED", `[]`)
	f.mustExec(t, m8p1Consequence, f.org, f.txn, 1, 1, none, "UNKNOWN", `["github.repo.deploy_triggers is not known"]`)
	f.mustExec(t, m8p1Consequence, f.org, f.txn, 2, 0, none, "NOT_TRIGGERED", `[]`)
	f.want(t, m7rForeignKey, "without a receipt", m8p1Consequence, f.org, f.txn, 4, 0, none, "PREDICTED", `[]`)
	f.want(t, m5Unique, "one position twice", m8p1Consequence, f.org, f.txn, 1, 0, none, "PREDICTED", `[]`)
	f.want(t, m5Check, "unknown without why", m8p1Consequence, f.org, f.txn, 3, 0, none, "UNKNOWN", `[]`)
	f.want(t, m5Check, "why without unknown", m8p1Consequence, f.org, f.txn, 3, 0, none, "PREDICTED", `["x"]`)
	f.want(t, m5Check, "environments not predicted", m8p1Consequence, f.org, f.txn, 3, 0, []string{"production"}, "NOT_TRIGGERED", `[]`)
	f.want(t, m5Check, "another state", m8p1Consequence, f.org, f.txn, 3, 0, none, "AUTHORIZED", `[]`)
	f.want(t, m5Denied, "UPDATE decision_consequences", "UPDATE pc.decision_consequences SET state = state")
	f.want(t, m5Denied, "DELETE decision_consequences", "DELETE FROM pc.decision_consequences")
	var audit bool
	d.AdminQueryRow(t, `SELECT has_table_privilege('pc_audit_ro', 'pc.decision_consequences', 'SELECT')`, nil, &audit)
	if !audit {
		t.Fatal("pc_audit_ro cannot read decision_consequences")
	}
}
