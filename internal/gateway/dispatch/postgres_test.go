// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/gateway/pgdispatch"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pcpostgres "github.com/katocxl/pantherclaw/packages/pc-postgres"
)

func shopConfig() *pb.PostgresConfig {
	col := func(n, ty, cl string) *pb.PostgresColumn { return &pb.PostgresColumn{Name: n, Type: ty, Class: cl} }
	return &pb.PostgresConfig{
		Host: "db.example.com", Database: "shop", User: "reader", Sslmode: "verify-full",
		Tables: []*pb.PostgresTable{
			{Schema: "shop", Name: "customers", ScopeKey: "customer", ScopeColumn: "id", Columns: []*pb.PostgresColumn{
				col("id", "bigint", "public"), col("email", "text", "pii"), col("tier", "text", "public"), col("ssn", "text", "secret"),
			}},
			{Schema: "shop", Name: "orders", Columns: []*pb.PostgresColumn{
				col("id", "bigint", "public"), col("customer_id", "bigint", "public"), col("amount", "numeric", "internal"), col("status", "text", "public"),
			}},
		},
	}
}

func pgMapper(t *testing.T) (*defs.Package, *mapping.Mapper) {
	t.Helper()
	pkg, err := manifest.Decode(pcpostgres.Package)
	if err != nil {
		t.Fatal(err)
	}
	m, err := mapping.New(pkg, celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	return pkg, m
}

func pgContext() mapping.Context {
	return mapping.Context{
		Org: ids.NewV7().String(), Env: ids.NewV7().String(), RunID: ids.NewV7().String(), ActionID: ids.NewV7().String(), AgentInstance: ids.NewV7().String(), Connection: ids.NewV7().String(),
	}
}

// TestHR307_FacesBuildTheSameStatement: an MCP tool call and the HTTP
// route for one query map to the same action and build one statement,
// whose SQL holds no value the agent sent (F099, HR-307).
func TestHR307_FacesBuildTheSameStatement(t *testing.T) {
	pkg, m := pgMapper(t)
	tc := pgContext()
	body := `{"table":"shop.orders","columns":["id","amount"],"filters":[{"column":"status","op":"eq","value":"paid' OR '1'='1"}],` +
		`"order_by":["amount:desc"],"limit":5}`
	viaMCP, err := m.MCP(context.Background(), tc, "query_rows", []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	viaHTTP, err := m.HTTPRequest(context.Background(), tc, "POST", "/v1/query", "", "application/json", []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	// One action but for its channel.
	x, y := viaMCP.Action, viaHTTP.Action
	if x.Operation != y.Operation || x.Route != y.Route || x.Target != y.Target || string(x.Params) != string(y.Params) || x.Channel == y.Channel {
		t.Fatalf("the faces map to different actions:\n%+v\n%+v", viaMCP.Action, viaHTTP.Action)
	}
	def, _ := pkg.Definition(viaMCP.Action.Operation)
	plan, err := pgQuery(shopConfig(), def, viaMCP.Action)
	if err != nil {
		t.Fatal(err)
	}
	st := plan.statement
	if strings.Contains(st.SQL, "paid") || !strings.Contains(st.SQL, `ORDER BY "shop"."orders"."amount" DESC LIMIT 6`) || st.Args[0] != "paid' OR '1'='1" {
		t.Fatalf("statement %s %v", st.SQL, st.Args)
	}
}

func TestPgQuery_Operations(t *testing.T) {
	pkg, m := pgMapper(t)
	call := func(tool, args string) (pgPlan, error) {
		t.Helper()
		p, err := m.MCP(context.Background(), pgContext(), tool, []byte(args))
		if err != nil {
			t.Fatalf("%s %s: %v", tool, args, err)
		}
		def, _ := pkg.Definition(p.Action.Operation)
		return pgQuery(shopConfig(), def, p.Action)
	}
	plan, err := call("aggregate_rows", `{"table":"shop.orders","group_by":["status"],"measures":["count:*","sum:amount"]}`)
	if err != nil || !strings.Contains(plan.statement.SQL, "HAVING count(*) >= 5") {
		t.Fatalf("aggregate %v %v", plan.statement, err)
	}
	plan, err = call("describe_tables", `{"database":"shop"}`)
	if err != nil || plan.statement != nil {
		t.Fatalf("describe %v %v", plan, err)
	}
	if _, err := call("describe_tables", `{"database":"other"}`); !errors.Is(err, errDatabaseMismatch) {
		t.Fatalf("other database: %v", err)
	}
	for args, code := range map[string]string{
		`{"table":"shop.secrets","columns":["id"]}`:                                                   pgdispatch.CodeTableNotAllowed,
		`{"table":"shop.customers","columns":["password"]}`:                                           pgdispatch.CodeColumnNotAllowed,
		`{"table":"shop.customers","columns":["id"],"order_by":["ssn:asc"]}`:                          pgdispatch.CodeColumnNotAllowed,
		`{"table":"shop.customers","columns":["id"],"filters":[{"column":"ssn","op":"is_null"}]}`:     pgdispatch.CodeColumnNotAllowed,
		`{"table":"shop.orders","columns":["id"],"filters":[{"column":"id","op":"eq","value":"1;"}]}`: pgdispatch.CodeQueryInvalid,
	} {
		if _, err := call("query_rows", args); pgdispatch.CodeOf(err) != code {
			t.Errorf("%s: %v, want %s", args, err, code)
		}
	}
	if _, err := call("aggregate_rows", `{"table":"shop.customers","measures":["max:email"]}`); pgdispatch.CodeOf(err) != pgdispatch.CodeColumnNotAllowed {
		t.Errorf("max of pii: %v", err)
	}
	// A limit clamped to zero is refused, never read as no limit (D98).
	p, err := m.MCP(context.Background(), pgContext(), "query_rows", []byte(`{"table":"shop.orders","columns":["id"],"limit":5}`))
	if err != nil {
		t.Fatal(err)
	}
	p.Action.Params = []byte(`{"columns":["id"],"limit":"0"}`)
	def, _ := pkg.Definition(p.Action.Operation)
	if _, err := pgQuery(shopConfig(), def, p.Action); err == nil {
		t.Errorf("limit 0: %v", err)
	}
	if _, err := pgQuery(nil, &defs.Definition{}, actionir.ActionIR{}); !errors.Is(err, errNoPostgresConfig) {
		t.Errorf("no config: %v", err)
	}
}

// TestHR307_MappingRefusesUnreviewedShapes: the reviewed input schema and
// the strict query_filter decoding refuse what the builder never sees.
func TestHR307_MappingRefusesUnreviewedShapes(t *testing.T) {
	_, m := pgMapper(t)
	for _, args := range []string{
		`{"table":"shop.orders","columns":["id"],"sql":"DELETE FROM shop.orders"}`,
		`{"table":"Shop.Orders","columns":["id"]}`,
		`{"table":"shop.orders","columns":["id; DROP TABLE x"]}`,
		`{"table":"shop.orders","columns":["id"],"filters":[{"column":"id","op":"eq","value":1}]}`,
		`{"table":"shop.orders","columns":["id"],"filters":[{"column":"id","op":"or","value":"1"}]}`,
		`{"table":"shop.orders","columns":["id"],"filters":[{"column":"id","op":"eq","value":"1","raw":"x"}]}`,
		`{"table":"shop.orders","columns":["id"],"order_by":["id:asc; DROP"]}`,
		`{"table":"shop.orders","columns":["id"],"limit":5000}`,
	} {
		if _, err := m.MCP(context.Background(), pgContext(), "query_rows", []byte(args)); err == nil {
			t.Errorf("%s mapped", args)
		}
	}
}
