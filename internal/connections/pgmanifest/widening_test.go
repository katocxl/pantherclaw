// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgmanifest

import (
	"testing"

	capp "github.com/katocxl/pantherclaw/internal/connections/app"
)

func base() capp.PostgresConfig {
	return capp.PostgresConfig{
		Host: "db.example.test", Port: 5432, Database: "shop", User: "reader", SSLMode: capp.SSLVerifyFull,
		MaxRows: 200, StatementTimeoutMs: 5000, MaxResultBytes: 1 << 20, MinGroupSize: 5,
		Tables: []capp.PostgresTable{{Schema: "shop", Name: "customers", ScopeKey: "customer", ScopeColumn: "id", MaxRows: 50, Columns: []capp.PostgresColumn{
			{Name: "id", Type: "bigint", Class: "public"}, {Name: "email", Type: "text", Class: "pii"}, {Name: "ssn", Type: "text", Class: "secret"},
		}}},
	}
}

// TestWidening (G0 M14 D84): what reaches further is proposed; what only
// narrows applies at once.
func TestWidening(t *testing.T) {
	if w := Widening(base(), base()); len(w) != 0 {
		t.Fatalf("unchanged: %v", w)
	}
	for name, mut := range map[string]func(*capp.PostgresConfig){
		"column removed":   func(c *capp.PostgresConfig) { c.Tables[0].Columns = c.Tables[0].Columns[:2] },
		"table removed":    func(c *capp.PostgresConfig) { c.Tables = nil },
		"class raised":     func(c *capp.PostgresConfig) { c.Tables[0].Columns[0].Class = "internal" },
		"rows lowered":     func(c *capp.PostgresConfig) { c.MaxRows = 100 },
		"timeout lowered":  func(c *capp.PostgresConfig) { c.StatementTimeoutMs = 1000 },
		"bytes lowered":    func(c *capp.PostgresConfig) { c.MaxResultBytes = 4096 },
		"min group raised": func(c *capp.PostgresConfig) { c.MinGroupSize = 10 },
		"table rows down":  func(c *capp.PostgresConfig) { c.Tables[0].MaxRows = 10 },
		"scope added":      func(c *capp.PostgresConfig) { c.Tables[0].ScopeKey, c.Tables[0].ScopeColumn = "customer", "id" },
		"internal off":     func(c *capp.PostgresConfig) {},
	} {
		next := base()
		mut(&next)
		if w := Widening(base(), next); len(w) != 0 {
			t.Errorf("%s widens: %v", name, w)
		}
	}
	for name, mut := range map[string]func(*capp.PostgresConfig){
		"new table": func(c *capp.PostgresConfig) {
			c.Tables = append(c.Tables, capp.PostgresTable{Schema: "shop", Name: "orders"})
		},
		"new column": func(c *capp.PostgresConfig) {
			c.Tables[0].Columns = append(c.Tables[0].Columns, capp.PostgresColumn{Name: "tier", Type: "text", Class: "public"})
		},
		"class lowered":     func(c *capp.PostgresConfig) { c.Tables[0].Columns[1].Class = "public" },
		"secret to pii":     func(c *capp.PostgresConfig) { c.Tables[0].Columns[2].Class = "pii" },
		"type changed":      func(c *capp.PostgresConfig) { c.Tables[0].Columns[0].Type = "text" },
		"rows raised":       func(c *capp.PostgresConfig) { c.MaxRows = 1000 },
		"timeout raised":    func(c *capp.PostgresConfig) { c.StatementTimeoutMs = 30000 },
		"bytes raised":      func(c *capp.PostgresConfig) { c.MaxResultBytes = 4 << 20 },
		"min group lowered": func(c *capp.PostgresConfig) { c.MinGroupSize = 2 },
		"table rows up":     func(c *capp.PostgresConfig) { c.Tables[0].MaxRows = 0 },
		"scope removed":     func(c *capp.PostgresConfig) { c.Tables[0].ScopeKey, c.Tables[0].ScopeColumn = "", "" },
		"internal on":       func(c *capp.PostgresConfig) { c.Internal = true },
		"another host":      func(c *capp.PostgresConfig) { c.Host = "other.example.test" },
		"another role":      func(c *capp.PostgresConfig) { c.User = "admin" },
		"weaker TLS":        func(c *capp.PostgresConfig) { c.SSLMode = capp.SSLRequire },
		"another CA":        func(c *capp.PostgresConfig) { c.CAPEM = "pem" },
	} {
		next := base()
		mut(&next)
		if w := Widening(base(), next); len(w) == 0 {
			t.Errorf("%s does not widen", name)
		}
	}
}
