// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package gateway

import (
	"net/http"
	"testing"

	"github.com/katocxl/pantherclaw/internal/gateway/pgtarget/pgtargettest"
)

// TestHR660_APooledDispatchReportsThePoolsCredential: the first postgres
// dispatch opens the sealed password and its pool; later dispatches reuse
// the pool without opening the credential again, and each reports the
// credential id and version the pool was opened with.
// Covers: F952
func TestHR660_APooledDispatchReportsThePoolsCredential(t *testing.T) {
	tg := pgtargettest.New(t)
	h := setup(t, withPostgres(t, tg, false))
	for range 3 {
		if _, r := pgRows(t, h, "/payments/v1/query", pgQuery); r.code != http.StatusOK {
			t.Fatalf("query: %d %s", r.code, r.body)
		}
	}
	recs := h.auth.snap().records
	if len(recs) != 3 {
		t.Fatalf("%d records", len(recs))
	}
	for i, rec := range recs {
		if u := rec.GetCredentialUsed(); u.GetCredentialId() != h.conn.Credential.GetId() || u.GetVersion() != 1 {
			t.Errorf("dispatch %d reported %v, want %s version 1", i+1, u, h.conn.Credential.GetId())
		}
	}
}
