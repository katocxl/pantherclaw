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

// pkgRule is a package rule's id.
const pkgRule = "merge-triggers-deployment"

const m17rChained = `INSERT INTO pc.decision_consequences (org_id, transaction_id, evaluation, position, rule_id, operation, target_type,
	target_id, state, facts_digest, depth, parent_position, source)
	VALUES ($1, $2, 1, $3, $7, 'github.deployment.trigger', 'github.repository', 'acme/payments', 'PREDICTED',
	'sha256:` + "0000000000000000000000000000000000000000000000000000000000000000" + `', $4, $5, $6)`

// TestM17Rules_ConsequenceChainSchema: a row written without the chain
// columns is a depth-1 package consequence; a deeper one names an earlier
// position of the same evaluation as its parent, at most four deep, and a
// depth-1 one names none; the source is a package or a customer rule,
// and only a customer rule has a cx. id.
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
	f.mustExec(t, m17rChained, f.org, f.txn, 1, 2, 0, "customer", "cx.deploy-settings")
	f.mustExec(t, m17rChained, f.org, f.txn, 2, 3, 1, "package", pkgRule)
	f.want(t, m5Check, "deeper without a parent", m17rChained, f.org, f.txn, 3, 2, nil, "package", pkgRule)
	f.want(t, m5Check, "depth 1 with a parent", m17rChained, f.org, f.txn, 3, 1, 0, "package", pkgRule)
	f.want(t, m5Check, "parent after the child", m17rChained, f.org, f.txn, 3, 2, 4, "package", pkgRule)
	f.want(t, m5Check, "parent is itself", m17rChained, f.org, f.txn, 3, 2, 3, "package", pkgRule)
	f.want(t, m5Check, "five deep", m17rChained, f.org, f.txn, 3, 5, 2, "package", pkgRule)
	f.want(t, m5Check, "another source", m17rChained, f.org, f.txn, 3, 2, 0, "model", pkgRule)
	f.want(t, m5Check, "a customer rule as a package one", m17rChained, f.org, f.txn, 3, 2, 0, "package", "cx.deploy-settings")
	f.want(t, m5Check, "a package rule as a customer one", m17rChained, f.org, f.txn, 3, 2, 0, "customer", pkgRule)
	f.want(t, m5Check, "another rule id", m17rChained, f.org, f.txn, 3, 2, 0, "customer", "cx.")
}

const m17rRule = `INSERT INTO pc.customer_consequence_rules (org_id, id, rule_id, version, body, digest, proposed_by, approved_by, state)
	VALUES ($1, $2, $3, $4, '{}', $5, $6, $7, $8)`

// TestHR453_CustomerRuleVersionsNeedTwoPeople: a version is approved by
// someone other than its proposer, is ACTIVE only with an approver, one
// per rule, and only moves forward; its body never changes, and auditors
// never read it. Rule ids start with cx.
//
// Covers: F405
func TestHR453_CustomerRuleVersionsNeedTwoPeople(t *testing.T) {
	d := dbtest.New(t)
	f := newM5Fixture(t, d.AppPool(t))
	bob := m5ID()
	f.mustExec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'bob')", f.org, bob)
	digest := make([]byte, 32)
	v1, v2 := m5ID(), m5ID()
	f.mustExec(t, m17rRule, f.org, v1, "cx.deploy-pages", 1, digest, f.user, bob, "ACTIVE")
	f.mustExec(t, m17rRule, f.org, v2, "cx.deploy-pages", 2, digest, f.user, nil, "PROPOSED")
	f.want(t, m5Check, "approved by its proposer", m17rRule, f.org, m5ID(), "cx.deploy-pages", 3, digest, f.user, f.user, "PROPOSED")
	f.want(t, m5Check, "ACTIVE without an approver", m17rRule, f.org, m5ID(), "cx.other", 1, digest, f.user, nil, "ACTIVE")
	f.want(t, m5Unique, "two ACTIVE versions", m17rRule, f.org, m5ID(), "cx.deploy-pages", 3, digest, f.user, bob, "ACTIVE")
	f.want(t, m5Check, "a package rule id", m17rRule, f.org, m5ID(), "deploy-pages", 1, digest, f.user, nil, "PROPOSED")
	f.want(t, m5Check, "a short digest", m17rRule, f.org, m5ID(), "cx.other", 1, digest[:31], f.user, nil, "PROPOSED")
	f.mustExec(t, "UPDATE pc.customer_consequence_rules SET state = 'RETIRED' WHERE id = $1", v1)
	f.want(t, m5Check, "RETIRED back to ACTIVE", "UPDATE pc.customer_consequence_rules SET state = 'ACTIVE' WHERE id = $1", v1)
	f.want(t, m5Check, "an approver without ACTIVE", "UPDATE pc.customer_consequence_rules SET approved_by = $2 WHERE id = $1", v2, bob)
	f.mustExec(t, "UPDATE pc.customer_consequence_rules SET state = 'ACTIVE', approved_by = $2 WHERE id = $1", v2, bob)
	f.want(t, m5Check, "another approver", "UPDATE pc.customer_consequence_rules SET approved_by = $2 WHERE id = $1", v2, f.user)
	f.want(t, m5Denied, "UPDATE a body", "UPDATE pc.customer_consequence_rules SET body = body")
	f.want(t, m5Denied, "DELETE a version", "DELETE FROM pc.customer_consequence_rules")
	var body, meta bool
	d.AdminQueryRow(t, `SELECT has_column_privilege('pc_audit_ro', 'pc.customer_consequence_rules', 'body', 'SELECT'),
		has_column_privilege('pc_audit_ro', 'pc.customer_consequence_rules', 'digest', 'SELECT')`, nil, &body, &meta)
	if body || !meta {
		t.Fatalf("pc_audit_ro reads the body %v, the digest %v; want false, true", body, meta)
	}
}
