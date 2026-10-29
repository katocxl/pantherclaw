// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
)

// These tests check the schema's second line of defense for G0 M17 stream
// S17b (migration 00208): the pipeline builds chains the same way first.
// Names are prefixed m17r so that they never collide with other
// milestones' schema tests in this package.

const m17rChained = `INSERT INTO pc.decision_consequences (org_id, transaction_id, evaluation, position, rule_id, operation, target_type,
	target_id, state, facts_digest, depth, parent_position, source)
	VALUES ($1, $2, 1, $3, 'merge-triggers-deployment', 'github.deployment.trigger', 'github.repository', 'acme/payments', 'PREDICTED',
	'sha256:` + "0000000000000000000000000000000000000000000000000000000000000000" + `', $4, $5, $6)`

// TestM17Rules_ConsequenceChainSchema: a row written without the chain
// columns is a depth-1 package consequence; a deeper one names an earlier
// position of the same evaluation as its parent, at most four deep, and a
// depth-1 one names none; the source is a package or a customer rule.
//
// Covers: F411
func TestM17Rules_ConsequenceChainSchema(t *testing.T) {
	d := dbtest.New(t)
	f := m7rFixture(t, d)
	f.mustExec(t, m8p1Consequence, f.org, f.txn, 1, 0, []string{}, "PREDICTED", `[]`)
	var depth int
	var source string
	d.AdminQueryRow(t, `SELECT depth, source FROM pc.decision_consequences WHERE transaction_id = $1 AND position = 0`, []any{f.txn}, &depth, &source)
	if depth != 1 || source != "package" {
		t.Fatalf("defaults = %d, %q; want 1, package", depth, source)
	}
	f.mustExec(t, m17rChained, f.org, f.txn, 1, 2, 0, "customer")
	f.mustExec(t, m17rChained, f.org, f.txn, 2, 3, 1, "package")
	f.want(t, m5Check, "deeper without a parent", m17rChained, f.org, f.txn, 3, 2, nil, "package")
	f.want(t, m5Check, "depth 1 with a parent", m17rChained, f.org, f.txn, 3, 1, 0, "package")
	f.want(t, m5Check, "parent after the child", m17rChained, f.org, f.txn, 3, 2, 4, "package")
	f.want(t, m5Check, "parent is itself", m17rChained, f.org, f.txn, 3, 2, 3, "package")
	f.want(t, m5Check, "five deep", m17rChained, f.org, f.txn, 3, 5, 2, "package")
	f.want(t, m5Check, "another source", m17rChained, f.org, f.txn, 3, 2, 0, "model")
}
