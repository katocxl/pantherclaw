// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package migrations_test

import (
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
)

// These tests check the schema's second line of defense for M7 slice B10,
// evidence packs (G0 M7 design decision 15, migration 00074): the
// application enforces the same rules first. Names are prefixed m7p so that
// they never collide with other milestones' schema tests in this package.

const (
	m7pPack = `INSERT INTO pc.evidence_packs (org_id, id, created_by, scope_kind, scope, include)
		VALUES ($1, $2, $3, 'run', '{"kind":"run"}', '{"receipts":true}')`
	m7pReady = `UPDATE pc.evidence_packs SET state = 'READY', manifest = repeat('m', 32), manifest_sha256 = ` + m5Hash + `,
		content = $3, content_sha256 = ` + m5Hash + `, content_size = 64, items = 1, ready_at = now(), expires_at = now() + interval '7 days'
		WHERE org_id = $1 AND id = $2`
)

// TestHR196_EvidencePacksChangeOnlyByTheirStateAndAreNeverDeleted: pc_app
// inserts a pack and moves it to READY with its manifest and content; it
// cannot delete a pack, change who made it or its scope, keep content on
// an expired pack, make a ready pack without content, or set an expiry
// other than 7 days after ready. Auditors read packs and their manifests,
// never the content.
func TestHR196_EvidencePacksChangeOnlyByTheirStateAndAreNeverDeleted(t *testing.T) {
	d := dbtest.New(t)
	f := newM5Fixture(t, d.AppPool(t))
	id := m5ID()
	f.mustExec(t, m7pPack, f.org, id, f.user)
	f.want(t, m5Check, "a ready pack without content", `UPDATE pc.evidence_packs SET state = 'READY' WHERE org_id = $1 AND id = $2`, f.org, id)
	f.want(t, m5Check, "an expiry other than 7 days", `UPDATE pc.evidence_packs SET state = 'READY', manifest = repeat('m', 32),
		content = repeat('c', 64)::bytea, ready_at = now(), expires_at = now() + interval '8 days' WHERE org_id = $1 AND id = $2`, f.org, id)
	f.want(t, m5Check, "a failed pack without a code", `UPDATE pc.evidence_packs SET state = 'FAILED' WHERE org_id = $1 AND id = $2`, f.org, id)
	f.mustExec(t, m7pReady, f.org, id, []byte("PK content of a pack, sixty-four bytes long, padded to the size."))
	f.want(t, m5Check, "an expired pack keeping its content", `UPDATE pc.evidence_packs SET state = 'EXPIRED' WHERE org_id = $1 AND id = $2`, f.org, id)
	f.mustExec(t, `UPDATE pc.evidence_packs SET state = 'EXPIRED', content = NULL WHERE org_id = $1 AND id = $2`, f.org, id)
	f.want(t, m5Denied, "DELETE evidence_packs", "DELETE FROM pc.evidence_packs")
	f.want(t, m5Denied, "change the creator", "UPDATE pc.evidence_packs SET created_by = created_by")
	f.want(t, m5Denied, "change the scope", "UPDATE pc.evidence_packs SET scope = scope")
	f.want(t, m7pForeignKey, "a creator who is no person of the org", m7pPack, f.org, m5ID(), m5ID())
	var manifest, content bool
	d.AdminQueryRow(t, `SELECT has_column_privilege('pc_audit_ro', 'pc.evidence_packs', 'manifest', 'SELECT'),
		has_column_privilege('pc_audit_ro', 'pc.evidence_packs', 'content', 'SELECT')`, nil, &manifest, &content)
	if !manifest || content {
		t.Fatalf("pc_audit_ro: manifest=%v content=%v, want true, false", manifest, content)
	}
}

const m7pForeignKey = "23503"
