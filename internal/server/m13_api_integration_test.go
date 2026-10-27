// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package server

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/credential"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestM13_APIConformance starts a disposable migrated database and real API
// wiring. The locked build-only Schemathesis tool sends read-only positive
// and negative inputs over HTTP with a real, rotating browser session.
func TestM13_APIConformance(t *testing.T) {
	if os.Getenv("PC_TEST_API_SCHEMA") != "1" {
		t.Skip("opt in with PC_TEST_API_SCHEMA=1 and install the locked tools/api environment")
	}
	d := dbtest.New(t)
	pool := d.AppPool(t)
	ctx := context.Background()
	org, user := ids.New[ids.Org](), ids.NewV7()
	secret, err := credential.New(credential.BrowserSession, "", org)
	if err != nil {
		t.Fatal(err)
	}
	err = pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{"INSERT INTO pc.orgs(id,name) VALUES($1,'api-assurance')", []any{org}},
			{"INSERT INTO pc.org_containment(org_id) VALUES($1)", []any{org}},
			{"INSERT INTO pc.users(org_id,id,issuer,subject) VALUES($1,$2,'https://api-assurance.test','person')", []any{org, user}},
			{"INSERT INTO pc.role_bindings(org_id,id,role,user_id,scope_type,created_by) VALUES($1,$2,'org_admin',$3,'ORG','api-assurance')", []any{org, ids.NewV7(), user}},
			{"INSERT INTO pc.sessions(org_id,id,user_id,secret_hash,provider,roles_digest,expires_at) VALUES($1,$2,$3,$4,'test',$5,now()+interval '1 hour')", []any{org, ids.NewV7(), user, secret.Hash(), make([]byte, 32)}},
		} {
			if _, err := tx.Exec(ctx, q.sql, q.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	base := serveForTest(t, testConfig(t, d, RoleAPI, func(cfg map[string]any) {
		cfg["billing"] = map[string]any{"mode": "off"}
	}))
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	// No secret is an argument or file. Python also redacts any rotated
	// session cookie before reporting a failed property check.
	cmd := exec.CommandContext(runCtx, "uv", "run", "--locked", "--project", filepath.Join(root, "tools", "api"), "pytest", filepath.Join(root, "tools", "api", "test_api.py")) //nolint:gosec // Fixed executable and trusted repository script; no shell.
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "PC_API_TEST_URL="+base, "PC_API_TEST_COOKIE="+secret.Reveal())
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		// Keep the original bootstrap cookie out even if Python fails before
		// installing its own sanitization wrapper.
		text := strings.ReplaceAll(out.String(), secret.Reveal(), "[REDACTED]")
		t.Fatalf("API conformance: %v\n%s", err, text)
	}
	t.Log(out.String())
}
