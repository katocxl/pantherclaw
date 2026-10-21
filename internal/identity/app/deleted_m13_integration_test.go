// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"testing"

	adomain "github.com/katocxl/pantherclaw/internal/agents/domain"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
)

// TestHR392_WorkloadsOfADeletedOrgFailClosed: once its org is DELETED
// (D22), an org's workloads get no nonce and their proofs are not consumed,
// so no enrollment, token or verified request (each consumes its proof
// first), before any of the org's rows are removed.
func TestHR392_WorkloadsOfADeletedOrgFailClosed(t *testing.T) {
	w := newWorld(t)
	wl, inst, _ := w.admitted(t, adomain.ContextCI)
	if _, err := w.token(wl, t, inst, ""); err != nil {
		t.Fatalf("before deletion: %v", err)
	}
	c := w.checked(t, newWorkload(), enrollURL, nil) // a nonce taken before
	w.exec(t, "UPDATE pc.orgs SET state = 'DELETED' WHERE id = $1", w.org)
	ctx := context.Background()
	if _, err := w.svc.Nonce(ctx, w.org); err == nil {
		t.Fatal("a deleted org hands out nonces")
	}
	// Enroll, IssueToken and Identify all consume their proof first.
	wantPAP(t, "proof of a deleted org", w.svc.Consume(ctx, w.org, c), pap.CodeInvalidToken)
}
