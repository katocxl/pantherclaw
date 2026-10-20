// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp

import (
	"strings"
	"testing"

	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/connections/pgmanifest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestPostgresManifestPage (G0 M14 D84): the confirm page shows what
// serves now, the proposal with how it widens, its tables, columns,
// classes, limits and internal, and a confirm button naming the proposal's
// digest only for someone who may confirm.
func TestPostgresManifestPage(t *testing.T) {
	cfg := func(internal bool, class string) *capp.PostgresConfig {
		return &capp.PostgresConfig{
			Host: "db.example.test", Port: 5432, Database: "shop", User: "reader", SSLMode: "verify-full", Internal: internal,
			MaxRows: 200, StatementTimeoutMs: 5000, MaxResultBytes: 1 << 20, MinGroupSize: 5,
			Tables: []capp.PostgresTable{{Schema: "shop", Name: "customers", ScopeKey: "customer", ScopeColumn: "id", Columns: []capp.PostgresColumn{
				{Name: "id", Type: "bigint", Class: "public"}, {Name: "email", Type: "text", Class: class},
			}}},
		}
	}
	id := ids.NewV7()
	view := postgresManifestView{
		page: page{Title: "Postgres connection"},
		Manifest: pgmanifest.Manifest{
			Connection: id, Name: "warehouse", State: "ACTIVE", Current: cfg(false, "pii"), Proposed: cfg(true, "public"),
			Widening: []string{"internal turned on", "column shop.customers.email lowered from pii to public"}, Digest: strings.Repeat("ab", 32),
		},
		CanConfirm: true,
	}
	var b strings.Builder
	if err := pages.ExecuteTemplate(&b, "postgres_manifest.html", view); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"Serving now", "Proposed", "internal turned on", "lowered from pii to public", "<code>shop.customers</code> (scoped by customer on id)",
		"<code>email</code></td><td>text</td><td>pii", "<code>email</code></td><td>text</td><td>public", "<strong>yes</strong>",
		"at most 200 rows", `data-path="/connections/` + id.String() + `/postgres/confirm?digest=` + strings.Repeat("ab", 32) + `"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	view.CanConfirm = false
	b.Reset()
	if err := pages.ExecuteTemplate(&b, "postgres_manifest.html", view); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "data-action") || !strings.Contains(b.String(), "needs connection.manage") {
		t.Error("a confirm button for someone who may not confirm")
	}
}
