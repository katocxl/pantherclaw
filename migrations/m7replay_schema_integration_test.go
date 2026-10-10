// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
)

// These tests check the schema's second line of defense for M7 slice B7,
// decision replay (G0 M7 design decision 11): the application enforces the
// same rules first. Names are prefixed m7r so that they never collide with
// other milestones' schema tests in this package.

const (
	m7rForeignKey = "23503"
	m7rLedger     = `INSERT INTO pc.ledger_entries (org_id, id, kind, actor_type, actor_id, body) VALUES ($1, $2, 'receipt.test', 'test', 'test', '\x7b7d')`
	m7rReceipt    = `INSERT INTO pc.decision_receipts (org_id, transaction_id, evaluation, receipt_jws, ledger_entry_id)
		VALUES ($1, $2, $3, 'eyJhbGciOiJFZERTQSJ9.e30.sig', $4)`
	m7rInputs = `INSERT INTO pc.evaluation_inputs (org_id, transaction_id, evaluation, format_version, pipeline_version, inputs,
		inputs_sha256, truncated) VALUES ($1, $2, $3, 1, 1, $4, $5, $6)`
)

// m7rFixture is the M5 part 2 org and transaction with decision receipts
// for its first three evaluations.
func m7rFixture(t *testing.T, d *dbtest.DB) m5p2Fixture {
	t.Helper()
	f := newM5p2Fixture(t, newM5Fixture(t, d.AppPool(t)))
	for evaluation := 1; evaluation <= 3; evaluation++ {
		entry := m5ID()
		f.mustExec(t, m7rLedger, f.org, entry)
		f.mustExec(t, m7rReceipt, f.org, f.txn, evaluation, entry)
	}
	return f
}

func m7rSealed(n int) []byte { return []byte(strings.Repeat("s", n)) }

func TestHR055_EvaluationInputsAreAppendOnly(t *testing.T) {
	d := dbtest.New(t)
	f := m7rFixture(t, d)
	f.mustExec(t, m7rInputs, f.org, f.txn, 1, m7rSealed(64), m5Secret(1), false)
	f.want(t, m5Denied, "UPDATE evaluation_inputs", "UPDATE pc.evaluation_inputs SET inputs = inputs")
	f.want(t, m5Denied, "UPDATE a truncated mark", "UPDATE pc.evaluation_inputs SET truncated = truncated")
	f.want(t, m5Denied, "DELETE evaluation_inputs", "DELETE FROM pc.evaluation_inputs")
	f.want(t, m5Unique, "a second row for one evaluation", m7rInputs, f.org, f.txn, 1, m7rSealed(64), m5Secret(2), false)
	// Auditors see that inputs exist, never the sealed bytes.
	var meta, sealed bool
	d.AdminQueryRow(t, `SELECT has_column_privilege('pc_audit_ro', 'pc.evaluation_inputs', 'inputs_sha256', 'SELECT'),
		has_column_privilege('pc_audit_ro', 'pc.evaluation_inputs', 'inputs', 'SELECT')`, nil, &meta, &sealed)
	if !meta || sealed {
		t.Fatalf("pc_audit_ro: inputs_sha256=%v inputs=%v, want true, false", meta, sealed)
	}
}

func TestHR197_EvaluationInputsBelongToOneDecisionReceipt(t *testing.T) {
	d := dbtest.New(t)
	f := m7rFixture(t, d)
	f.want(t, m7rForeignKey, "inputs of an evaluation without a receipt", m7rInputs, f.org, f.txn, 4, m7rSealed(64), m5Secret(1), false)
	f.want(t, m7rForeignKey, "inputs of an unknown transaction", m7rInputs, f.org, m5ID(), 1, m7rSealed(64), m5Secret(1), false)
	f.want(t, m5Check, "evaluation 65", m7rInputs, f.org, f.txn, 65, m7rSealed(64), m5Secret(1), false)
	// Truncated rows keep only their digest; others keep at most 32 KiB
	// sealed (with the envelope's 33 bytes).
	f.want(t, m5Check, "truncated with inputs", m7rInputs, f.org, f.txn, 1, m7rSealed(64), m5Secret(1), true)
	f.want(t, m5Check, "inputs missing without truncation", m7rInputs, f.org, f.txn, 1, nil, m5Secret(1), false)
	f.want(t, m5Check, "inputs over the cap", m7rInputs, f.org, f.txn, 1, m7rSealed(32<<10+34), m5Secret(1), false)
	f.want(t, m5Check, "inputs shorter than an envelope", m7rInputs, f.org, f.txn, 1, m7rSealed(33), m5Secret(1), false)
	f.want(t, m5Check, "a digest that is not a SHA-256", m7rInputs, f.org, f.txn, 1, m7rSealed(64), []byte("short"), false)
	f.mustExec(t, m7rInputs, f.org, f.txn, 1, m7rSealed(32<<10+33), m5Secret(1), false)
	f.mustExec(t, m7rInputs, f.org, f.txn, 2, nil, m5Secret(2), true)
	f.mustExec(t, `INSERT INTO pc.evaluation_inputs (org_id, transaction_id, evaluation, format_version, pipeline_version,
		inputs, inputs_sha256) VALUES ($1, $2, 3, 1, 1, $3, $4)`, f.org, f.txn, m7rSealed(34), m5Secret(3))
}
