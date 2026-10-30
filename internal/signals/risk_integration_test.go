// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package signals

import (
	"net/http"
	"testing"
)

// TestHR441_AnAcceptedSignalWritesTheIdentityRisk: an accepted event
// writes pc.identity.risk about the person through the org's one built-in
// provider pc.signals, with its provenance; a second event reuses that
// provider.
// Covers: F366
func TestHR441_AnAcceptedSignalWritesTheIdentityRisk(t *testing.T) {
	f := newRxFixture(t)
	if a := f.post(t, f.org, f.tx, ContentType, f.token(t, f.key, f.tx, nil)); a.status != http.StatusAccepted {
		t.Fatalf("push: %+v", a)
	}
	q := `SELECT count(*) FROM pc.facts x JOIN pc.fact_providers p ON p.org_id = x.org_id AND p.id = x.provider_id
		WHERE x.name = 'pc.identity.risk' AND x.subject_type = 'user' AND x.subject_id = $1 AND p.builtin AND p.name = 'pc.signals'
		  AND x.source = 'pc.signals' AND x.method = 'rule'`
	if n := f.count(t, q, f.alice.String()); n != 1 {
		t.Fatalf("identity-risk facts = %d", n)
	}
	if a := f.post(t, f.org, f.tx, ContentType, f.token(t, f.key, f.tx, nil)); a.status != http.StatusAccepted {
		t.Fatalf("second push: %+v", a)
	}
	if n := f.count(t, "SELECT count(*) FROM pc.fact_providers WHERE builtin"); n != 1 {
		t.Fatalf("built-in providers = %d", n)
	}
}
