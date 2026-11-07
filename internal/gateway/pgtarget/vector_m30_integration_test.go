// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgtarget_test

import (
	"context"
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/gateway/pgtarget"
	"github.com/katocxl/pantherclaw/internal/gateway/pgtarget/pgtargettest"
)

func vectorCheck(t *testing.T, tg *pgtargettest.Target) []string {
	t.Helper()
	c := tg.Config(true)
	p, err := pgtarget.OpenVector(context.Background(), pgtarget.VectorConfig{Endpoint: c.Endpoint, Password: c.Password, Allowed: c.Allowed})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	findings, err := p.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return findings
}

// TestHR705_VectorstoreWriterRoleIsNotRefusedAsSuperuser: a role that may
// write, but is no superuser, is not refused for its role (G0 M30 D924:
// the read-only check of pc-postgres does not apply to this kind). The
// test cluster has no pgvector, so the extension finding is expected.
func TestHR705_VectorstoreWriterRoleIsNotRefusedAsSuperuser(t *testing.T) {
	tg := pgtargettest.New(t)
	findings := vectorCheck(t, tg)
	if slices.Contains(findings, "superuser") || slices.ContainsFunc(findings, func(f string) bool { return len(f) > 4 && f[:4] == "can " }) {
		t.Fatalf("findings %v", findings)
	}
}

// TestHR705_VectorstoreSuperuserRoleIsRefused: a superuser role fails the
// vectorstore connection check, so nothing dispatches through it.
func TestHR705_VectorstoreSuperuserRoleIsRefused(t *testing.T) {
	tg := pgtargettest.New(t)
	tg.AdminExec(t, "ALTER ROLE "+tg.Writer+" SUPERUSER")
	t.Cleanup(func() { tg.AdminExec(t, "ALTER ROLE "+tg.Writer+" NOSUPERUSER") })
	if findings := vectorCheck(t, tg); !slices.Contains(findings, "superuser") {
		t.Fatalf("findings %v", findings)
	}
}
