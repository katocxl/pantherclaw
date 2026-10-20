// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgtarget_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/gateway/pgdispatch"
	"github.com/katocxl/pantherclaw/internal/gateway/pgtarget"
	"github.com/katocxl/pantherclaw/internal/gateway/pgtarget/pgtargettest"
)

func open(t *testing.T, c pgtarget.Config) *pgtarget.Pool {
	t.Helper()
	p, err := pgtarget.Open(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

type answer struct {
	Columns         []string `json:"columns"`
	Rows            [][]any  `json:"rows"`
	Truncated       bool     `json:"truncated"`
	TruncatedValues bool     `json:"truncated_values"`
	Redacted        int      `json:"redacted"`
}

func run(t *testing.T, p *pgtarget.Pool, st *pgdispatch.Statement) answer {
	t.Helper()
	res, err := p.Run(context.Background(), st)
	if err != nil {
		t.Fatal(err)
	}
	var a answer
	if err := json.Unmarshal(res.Body, &a); err != nil {
		t.Fatalf("answer %s: %v", res.Body, err)
	}
	return a
}

func ptr(s string) *string { return &s }

// TestHR309_ReadOnlyRolePasses: the fixture's read-only role passes the
// role check, and a query through it answers as built.
func TestHR309_ReadOnlyRolePasses(t *testing.T) {
	tg := pgtargettest.New(t)
	p := open(t, tg.Config(false))
	findings, err := p.Check(context.Background())
	if err != nil || len(findings) != 0 {
		t.Fatalf("findings %v, err %v", findings, err)
	}
	st, err := pgdispatch.BuildRows(p.Manifest(), pgdispatch.Rows{
		Table: "shop.customers", Columns: []string{"id", "email", "ssn"}, OrderBy: []pgdispatch.Order{{Column: "id"}},
		Access: pgdispatch.Access{Classes: []pgdispatch.Class{pgdispatch.ClassPublic}},
	})
	if err != nil {
		t.Fatal(err)
	}
	a := run(t, p, st)
	if len(a.Rows) != 3 || a.Rows[0][0] != float64(1) || a.Rows[0][1] != "[redacted:pii]" || a.Rows[0][2] != "[redacted:secret]" || a.Redacted != 6 {
		t.Fatalf("answer %+v", a)
	}
}

// TestHR309_WritableRoleRefused: a role that can insert or update a
// manifest table, a superuser, and a manifest that does not match the
// database all fail the check.
func TestHR309_WritableRoleRefused(t *testing.T) {
	tg := pgtargettest.New(t)
	findings, err := open(t, tg.Config(true)).Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"can INSERT shop.orders", "can UPDATE support.tickets", "can INSERT a column of shop.customers"} {
		if !slices.Contains(findings, want) {
			t.Errorf("missing finding %q in %v", want, findings)
		}
	}
	// Column-level write grants count too.
	tg.AdminExec(t, "GRANT UPDATE (tier) ON shop.customers TO "+tg.ReadOnly)
	findings, err = open(t, tg.Config(false)).Check(context.Background())
	if err != nil || !slices.Equal(findings, []string{"can UPDATE a column of shop.customers"}) {
		t.Fatalf("column grant: %v %v", findings, err)
	}
	tg.AdminExec(t, "REVOKE UPDATE (tier) ON shop.customers FROM "+tg.ReadOnly, "ALTER ROLE "+tg.ReadOnly+" SUPERUSER")
	findings, _ = open(t, tg.Config(false)).Check(context.Background())
	if !slices.Contains(findings, "superuser") {
		t.Fatalf("superuser: %v", findings)
	}
	tg.AdminExec(t, "ALTER ROLE "+tg.ReadOnly+" NOSUPERUSER", "GRANT pg_write_all_data TO "+tg.ReadOnly)
	findings, _ = open(t, tg.Config(false)).Check(context.Background())
	if !slices.Contains(findings, "member of pg_write_all_data") {
		t.Fatalf("pg_write_all_data: %v", findings)
	}
	tg.AdminExec(t, "REVOKE pg_write_all_data FROM "+tg.ReadOnly)
	// A member that does not inherit could still SET ROLE (D98).
	tg.AdminExec(t, "ALTER ROLE "+tg.ReadOnly+" NOINHERIT", "GRANT pg_write_all_data TO "+tg.ReadOnly)
	findings, _ = open(t, tg.Config(false)).Check(context.Background())
	if !slices.Contains(findings, "member of pg_write_all_data") {
		t.Fatalf("NOINHERIT member: %v", findings)
	}
	tg.AdminExec(t, "REVOKE pg_write_all_data FROM "+tg.ReadOnly, "ALTER ROLE "+tg.ReadOnly+" INHERIT")
	// Views (and foreign tables) are not tables (D98).
	tg.AdminExec(t, "CREATE VIEW shop.gold AS SELECT id, tier FROM shop.customers", "GRANT SELECT ON shop.gold TO "+tg.ReadOnly)
	v := tg.Config(false)
	v.Manifest.Tables = append(v.Manifest.Tables, pgdispatch.Table{Schema: "shop", Name: "gold", Columns: []pgdispatch.Column{{Name: "id", Type: pgdispatch.TypeBigint, Class: pgdispatch.ClassPublic}}})
	findings, _ = open(t, v).Check(context.Background())
	if !slices.Equal(findings, []string{"shop.gold is not a table (relkind v)"}) {
		t.Fatalf("view: %v", findings)
	}
	c := tg.Config(false)
	c.Manifest.Tables[0].Columns[1].Type = pgdispatch.TypeInt
	c.Manifest.Tables[1].Columns = append(c.Manifest.Tables[1].Columns, pgdispatch.Column{Name: "missing", Type: pgdispatch.TypeText, Class: pgdispatch.ClassPublic})
	c.Manifest.Tables = append(c.Manifest.Tables, pgdispatch.Table{Schema: "shop", Name: "nope", Columns: []pgdispatch.Column{{Name: "id", Type: pgdispatch.TypeInt, Class: pgdispatch.ClassPublic}}})
	findings, _ = open(t, c).Check(context.Background())
	for _, want := range []string{`column shop.customers.name is "text", not int`, "column shop.orders.missing does not exist", "table shop.nope does not exist"} {
		if !slices.Contains(findings, want) {
			t.Errorf("missing finding %q in %v", want, findings)
		}
	}
}

// TestHR308_ReadOnlyTransaction: even a statement that pgdispatch would
// never build cannot write, the transaction is rolled back, and a
// statement past its timeout fails without hanging.
func TestHR308_ReadOnlyTransaction(t *testing.T) {
	tg := pgtargettest.New(t)
	c := tg.Config(true) // a role that could write outside the transaction
	c.Manifest.StatementTimeoutMS = 300
	p := open(t, c)
	for _, sql := range []string{
		`INSERT INTO shop.orders VALUES (99, 1, 1, 'x')`,
		`UPDATE shop.orders SET status = 'x'`,
		`CREATE TEMP TABLE t (x int)`,
		`SELECT pg_catalog.set_config('default_transaction_read_only', 'off', true); INSERT INTO shop.orders VALUES (98, 1, 1, 'x')`,
	} {
		if _, err := p.Run(context.Background(), &pgdispatch.Statement{SQL: sql, Limit: 1}); err == nil {
			t.Errorf("%s ran", sql)
		}
	}
	start := time.Now()
	_, err := p.Run(context.Background(), &pgdispatch.Statement{SQL: `SELECT pg_catalog.pg_sleep(5)`, Limit: 1})
	if !errors.Is(err, pgtarget.ErrTimeout) || time.Since(start) > 3*time.Second {
		t.Fatalf("timeout: %v after %s", err, time.Since(start))
	}
	// The pool still answers, and nothing was written.
	st, _ := pgdispatch.BuildAggregate(p.Manifest(), pgdispatch.Aggregate{Table: "shop.orders", Measures: []pgdispatch.Measure{{Func: "count", Column: "*"}}})
	if a := run(t, p, st); a.Rows[0][0] != float64(11) {
		t.Fatalf("orders %v", a.Rows)
	}
}

// TestHR307_ValuesAreParameters: hostile values reach the database only
// as parameters: they match nothing and change nothing, and sorting uses
// the column's type (D72).
func TestHR307_ValuesAreParameters(t *testing.T) {
	tg := pgtargettest.New(t)
	p := open(t, tg.Config(false))
	for _, v := range []string{`paid' OR '1'='1`, `x'); DELETE FROM shop.orders; --`, `%`, `_aid`, `\`} {
		st, err := pgdispatch.BuildRows(p.Manifest(), pgdispatch.Rows{
			Table: "shop.orders", Columns: []string{"id"},
			Filters: []pgdispatch.Filter{{Column: "status", Op: pgdispatch.OpPrefix, Value: ptr(v)}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if a := run(t, p, st); len(a.Rows) != 0 {
			t.Errorf("%q matched %v", v, a.Rows)
		}
	}
	st, _ := pgdispatch.BuildRows(p.Manifest(), pgdispatch.Rows{
		Table: "shop.orders", Columns: []string{"amount"}, OrderBy: []pgdispatch.Order{{Column: "amount"}}, Limit: 3,
	})
	a := run(t, p, st)
	if got := []any{a.Rows[0][0], a.Rows[1][0], a.Rows[2][0]}; !slices.Equal(got, []any{"5.00", "6.00", "7.00"}) || !a.Truncated {
		t.Fatalf("numeric sort %v truncated %v", got, a.Truncated)
	}
}

// TestHR312_SmallGroupsAbsent: a group below min_group_size is absent from
// the answer, not reported with a small count.
func TestHR312_SmallGroupsAbsent(t *testing.T) {
	tg := pgtargettest.New(t)
	p := open(t, tg.Config(false))
	st, err := pgdispatch.BuildAggregate(p.Manifest(), pgdispatch.Aggregate{
		Table: "shop.orders", GroupBy: []string{"customer_id"},
		Measures: []pgdispatch.Measure{{Func: "count", Column: "*"}, {Func: "sum", Column: "amount"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	a := run(t, p, st)
	// Customer 1 has 8 orders; customer 2 has 3, below the default 5.
	if len(a.Rows) != 1 || a.Rows[0][0] != float64(1) || a.Rows[0][1] != float64(8) || a.Rows[0][2] != "221.00" {
		t.Fatalf("groups %v", a.Rows)
	}
	st, _ = pgdispatch.BuildAggregate(p.Manifest(), pgdispatch.Aggregate{
		Table: "shop.orders", Measures: []pgdispatch.Measure{{Func: "max", Column: "amount"}},
		Filters: []pgdispatch.Filter{{Column: "customer_id", Op: pgdispatch.OpEq, Value: ptr("2")}},
	})
	if a := run(t, p, st); len(a.Rows) != 0 {
		t.Fatalf("filtered small group %v", a.Rows)
	}
}

// TestEncoder_LongValuesCutInSQL: a value of megabytes is cut in the
// database, so the answer stays within its limits (D72).
func TestEncoder_LongValuesCutInSQL(t *testing.T) {
	tg := pgtargettest.New(t)
	tg.AdminExec(t, "UPDATE support.tickets SET subject = repeat('x', 8 << 20) WHERE id = 100")
	c := tg.Config(false)
	c.Manifest.MaxResultBytes = 1 << 20
	p := open(t, c)
	st, _ := pgdispatch.BuildRows(p.Manifest(), pgdispatch.Rows{Table: "support.tickets", Columns: []string{"subject"}, OrderBy: []pgdispatch.Order{{Column: "id"}}})
	res, err := p.Run(context.Background(), st)
	if err != nil {
		t.Fatal(err)
	}
	if !res.TruncatedValues || len(res.Body) > 1<<20 || !strings.Contains(string(res.Body), strings.Repeat("x", pgdispatch.MaxValueChars)+`"`) {
		t.Fatalf("cut %v, %d bytes", res.TruncatedValues, len(res.Body))
	}
}

// TestHR330_TransportAndEgress: only verify-full TLS, or require for an
// internal endpoint with a pinned CA; a server without TLS, a wrong host
// name or another CA is refused; a private address needs internal.
func TestHR330_TransportAndEgress(t *testing.T) {
	tg := pgtargettest.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	refused := func(name string, c pgtarget.Config) {
		t.Helper()
		p, err := pgtarget.Open(ctx, c)
		if err == nil {
			_, err = p.Check(ctx)
			p.Close()
		}
		if err == nil {
			t.Errorf("%s: connected", name)
		}
	}
	for name, mut := range map[string]func(*pgtarget.Config){
		"disable":                  func(c *pgtarget.Config) { c.Endpoint.SSLMode = "disable" },
		"prefer":                   func(c *pgtarget.Config) { c.Endpoint.SSLMode = "prefer" },
		"require without internal": func(c *pgtarget.Config) { c.Endpoint.SSLMode = pgtarget.SSLRequire; c.Endpoint.Internal = false },
		"require without CA":       func(c *pgtarget.Config) { c.Endpoint.SSLMode = pgtarget.SSLRequire; c.Endpoint.CAPEM = "" },
		"bad CA": func(c *pgtarget.Config) {
			c.Endpoint.CAPEM = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
		},
	} {
		c := tg.Config(false)
		mut(&c)
		if _, err := pgtarget.Open(ctx, c); !errors.Is(err, pgtarget.ErrEndpoint) {
			t.Errorf("%s: %v", name, err)
		}
	}
	c := tg.Config(false)
	c.Endpoint.Internal = false
	refused("loopback without internal", c)
	c = tg.Config(false)
	c.Allowed = nil // a gateway whose operator allows no private prefix, as PantherClaw hosts them
	refused("internal without an operator prefix", c)
	c = tg.Config(false)
	c.Allowed = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	refused("loopback outside the operator's prefixes", c)
	named := pgtargettest.New(t, pgtargettest.NameOnly())
	c = named.Config(false)
	c.Endpoint.Host = "127.0.0.1" // not a name its certificate holds
	refused("wrong host name", c)
	c = tg.Config(false)
	c.Endpoint.CAPEM = pgtargettest.New(t).CAPEM // another CA
	refused("another CA", c)
	c = tg.Config(false)
	c.Endpoint.Port = 5433 // the cluster itself: no TLS
	refused("server without TLS", c)
	// require with the pinned CA checks the chain but not the name.
	c = tg.Config(false)
	c.Endpoint.SSLMode, c.Endpoint.Host = pgtarget.SSLRequire, "127.0.0.1"
	if findings, err := open(t, c).Check(ctx); err != nil || len(findings) != 0 {
		t.Fatalf("require: %v %v", findings, err)
	}
}

// TestHR307_PartitionsAndInheritance (D105): a partitioned table whose
// partitions are tables passes and is read whole; an ordinary table is
// read with ONLY, so an inheritance child's rows never join its answer.
func TestHR307_PartitionsAndInheritance(t *testing.T) {
	tg := pgtargettest.New(t)
	tg.AdminExec(t,
		"CREATE TABLE shop.events (id bigint, at date) PARTITION BY RANGE (at)",
		"CREATE TABLE shop.events_2026 PARTITION OF shop.events FOR VALUES FROM ('2026-01-01') TO ('2027-01-01') PARTITION BY RANGE (id)",
		"CREATE TABLE shop.events_2026_a PARTITION OF shop.events_2026 FOR VALUES FROM (0) TO (1000)",
		"INSERT INTO shop.events VALUES (1, '2026-10-17'), (2, '2026-10-18')",
		"GRANT SELECT ON shop.events TO "+tg.ReadOnly,
		"CREATE TABLE shop.orders_archive () INHERITS (shop.orders)",
		"INSERT INTO shop.orders_archive VALUES (99, 1, 1.00, 'paid')",
		"GRANT SELECT ON shop.orders_archive TO "+tg.ReadOnly,
	)
	c := tg.Config(false)
	c.Manifest.Tables = append(c.Manifest.Tables, pgdispatch.Table{Schema: "shop", Name: "events", Columns: []pgdispatch.Column{
		{Name: "id", Type: pgdispatch.TypeBigint, Class: pgdispatch.ClassPublic}, {Name: "at", Type: pgdispatch.TypeDate, Class: pgdispatch.ClassPublic},
	}})
	p := open(t, c)
	if findings, err := p.Check(context.Background()); err != nil || len(findings) != 0 {
		t.Fatalf("findings %v %v", findings, err)
	}
	if !p.Partitioned("shop.events") || p.Partitioned("shop.orders") {
		t.Fatal("partitioned tables not recognised")
	}
	m := p.Manifest()
	for i := range m.Tables {
		m.Tables[i].Partitioned = p.Partitioned(m.Tables[i].Ref())
	}
	st, _ := pgdispatch.BuildRows(m, pgdispatch.Rows{Table: "shop.events", Columns: []string{"id"}})
	if a := run(t, p, st); len(a.Rows) != 2 {
		t.Fatalf("partitioned rows %v", a.Rows)
	}
	st, _ = pgdispatch.BuildAggregate(m, pgdispatch.Aggregate{Table: "shop.orders", Measures: []pgdispatch.Measure{{Func: "count", Column: "*"}}})
	if a := run(t, p, st); a.Rows[0][0] != float64(11) {
		t.Fatalf("an inheritance child joined the answer: %v", a.Rows)
	}
}
