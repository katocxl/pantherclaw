// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package gateway

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/credentials/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/broker"
	"github.com/katocxl/pantherclaw/internal/gateway/pgtarget/pgtargettest"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// withPostgres makes the harness connection a postgres connection to the
// fixture database, its role's password sealed (G0 M14 D15, D16).
func withPostgres(t *testing.T, tg *pgtargettest.Target, writer bool) func(*harness) {
	return func(h *harness) {
		dir := t.TempDir()
		kek := filepath.Join(dir, "kek")
		if err := keys.GenerateKEKFile(kek); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "broker.json")
		if _, err := broker.Generate(t.Context(), path, []string{kek}); err != nil {
			t.Fatal(err)
		}
		key, err := broker.Load(t.Context(), path, []string{kek})
		if err != nil {
			t.Fatal(err)
		}
		h.broker = NewBroker(key, nil, nil)
		h.broker.id = "bk-1"
		c := tg.Config(writer)
		pub, _ := pccrypto.ParseSealPublicKey(key.PublicKey())
		bind := domain.Binding{Org: testOrg, Connection: connID, Version: 1, BrokerKey: "bk-1"}
		blob, err := pccrypto.Seal(pub, bind.Info(), domain.AAD, []byte(c.Password))
		if err != nil {
			t.Fatal(err)
		}
		h.pkgFile = "../../packages/pc-postgres/package.yaml"
		g := h.conn.GatewayConnection
		g.Kind, g.Package, g.AccessMode, g.AllowedHosts, g.BaseUrl = "postgres", "pc.postgres", "pantherclaw_held", nil, "postgres://unused"
		h.conn.Credential = &pb.SealedCredential{Id: ids.NewV7().String(), ConnectionId: connID, Version: 1, BrokerKeyId: "bk-1", Sealed: blob}
		col := func(n, ty, cl string) *pb.PostgresColumn { return &pb.PostgresColumn{Name: n, Type: ty, Class: cl} }
		g.Postgres = &pb.PostgresConfig{
			Host: c.Endpoint.Host, Port: int32(c.Endpoint.Port), Database: c.Endpoint.Database, User: c.Endpoint.User, //nolint:gosec // G115: a port
			Sslmode: "verify-full", CaPem: c.Endpoint.CAPEM, Internal: true, StatementTimeoutMs: 1000,
			Tables: []*pb.PostgresTable{
				{Schema: "shop", Name: "customers", ScopeKey: "customer", ScopeColumn: "id", Columns: []*pb.PostgresColumn{
					col("id", "bigint", "public"), col("name", "text", "pii"), col("email", "text", "pii"), col("tier", "text", "public"),
					col("ssn", "text", "secret"),
				}},
				{Schema: "shop", Name: "orders", ScopeKey: "customer", ScopeColumn: "customer_id", Columns: []*pb.PostgresColumn{
					col("id", "bigint", "public"), col("customer_id", "bigint", "public"), col("amount", "numeric", "internal"),
					col("status", "text", "public"),
				}},
			},
		}
	}
}

const pgQuery = `{"table":"shop.customers","columns":["id","email","ssn"],"filters":[{"column":"tier","op":"eq","value":"gold"}],"order_by":["id:asc"]}`

type pgAnswer struct {
	Columns  []string `json:"columns"`
	Rows     [][]any  `json:"rows"`
	Redacted int      `json:"redacted"`
}

// TestHR307_PostgresFacesAnswerAlike: a query through the HTTP face and the
// same query through the MCP face reach the database as one statement and
// answer the same rows (F099); secret values never leave the database.
func TestHR307_PostgresFacesAnswerAlike(t *testing.T) {
	tg := pgtargettest.New(t)
	h := setup(t, withPostgres(t, tg, false))
	r := h.do(t, http.MethodPost, "/payments/v1/query", pgQuery, nil)
	if r.code != http.StatusOK {
		t.Fatalf("http face: %d %s", r.code, r.body)
	}
	var viaHTTP pgAnswer
	if err := json.Unmarshal([]byte(r.body), &viaHTTP); err != nil {
		t.Fatal(err)
	}
	if len(viaHTTP.Rows) != 2 || viaHTTP.Rows[0][1] != "ada@example.com" || viaHTTP.Rows[0][2] != "[redacted:secret]" || viaHTTP.Redacted != 2 {
		t.Fatalf("http answer %+v", viaHTTP)
	}
	m := h.mcpCall(t, http.MethodPost, mcpPath, jsonRPC("tools/call", `"name":"query_rows","arguments":`+pgQuery), nil)
	if m.code != http.StatusOK || m.body.Result.IsError {
		t.Fatalf("mcp face: %d %+v", m.code, m.body)
	}
	var viaMCP pgAnswer
	if err := json.Unmarshal(m.body.Result.StructuredContent, &viaMCP); err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(viaHTTP)
	b, _ := json.Marshal(viaMCP)
	if string(a) != string(b) {
		t.Fatalf("faces differ:\n%s\n%s", a, b)
	}
	if strings.Contains(r.body, "111-11-1111") {
		t.Fatal("a secret value left the database")
	}
	tools := h.mcpCall(t, http.MethodPost, mcpPath, jsonRPC("tools/list", ""), nil)
	var names []string
	for _, tl := range tools.body.Result.Tools {
		names = append(names, tl.Name)
	}
	if strings.Join(names, ",") != "aggregate_rows,describe_tables,query_rows" {
		t.Fatalf("tools %v", names)
	}
}

// TestHR307_PostgresRefusalsSendNothing: a column outside the manifest,
// a filter on a secret column and a describe of another database are
// refused with their codes; the tables of the manifest are described.
func TestHR307_PostgresRefusalsSendNothing(t *testing.T) {
	tg := pgtargettest.New(t)
	h := setup(t, withPostgres(t, tg, false))
	for body, code := range map[string]string{
		`{"table":"shop.customers","columns":["password"]}`:                                                  "column_not_allowed",
		`{"table":"shop.customers","columns":["id"],"filters":[{"column":"ssn","op":"prefix","value":"1"}]}`: "column_not_allowed",
		`{"table":"support.tickets","columns":["id"]}`:                                                       "table_not_allowed",
	} {
		r := h.do(t, http.MethodPost, "/payments/v1/query", body, nil)
		if r.refusal.Error != code {
			t.Errorf("%s: %d %s", body, r.code, r.body)
		}
	}
	r := h.do(t, http.MethodGet, "/payments/v1/tables?database=other", "", nil)
	if r.refusal.Error != "target_mismatch" {
		t.Errorf("other database: %d %s", r.code, r.body)
	}
	r = h.do(t, http.MethodGet, "/payments/v1/tables?database="+tg.Database, "", nil)
	if r.code != http.StatusOK || !strings.Contains(r.body, `"table":"shop.orders"`) || strings.Contains(r.body, "ssn") {
		t.Errorf("describe: %d %s", r.code, r.body)
	}
}

// TestHR309_WritableRoleDispatchesNothing: through a role that can write a
// manifest table, the gateway refuses every query.
func TestHR309_WritableRoleDispatchesNothing(t *testing.T) {
	tg := pgtargettest.New(t)
	h := setup(t, withPostgres(t, tg, true))
	r := h.do(t, http.MethodPost, "/payments/v1/query", pgQuery, nil)
	if r.refusal.Error != "role_not_read_only" {
		t.Fatalf("writer: %d %s", r.code, r.body)
	}
}

// TestHR312_PostgresAggregateThroughTheGateway: an aggregate leaves out
// groups below the minimum size.
func TestHR312_PostgresAggregateThroughTheGateway(t *testing.T) {
	tg := pgtargettest.New(t)
	h := setup(t, withPostgres(t, tg, false))
	r := h.do(t, http.MethodPost, "/payments/v1/aggregate", `{"table":"shop.orders","group_by":["customer_id"],"measures":["count:*"]}`, nil)
	var a pgAnswer
	if err := json.Unmarshal([]byte(r.body), &a); err != nil || len(a.Rows) != 1 || a.Rows[0][0] != float64(1) {
		t.Fatalf("aggregate %d %s", r.code, r.body)
	}
}

// TestHR307_PostgresWithoutConfigurationSendsNothing: a postgres
// connection whose configuration did not reach the gateway is refused
// CANNOT_AUTHORIZE before anything is committed or sent (D85).
func TestHR307_PostgresWithoutConfigurationSendsNothing(t *testing.T) {
	tg := pgtargettest.New(t)
	h := setup(t, withPostgres(t, tg, false), func(h *harness) { h.conn.Postgres = nil })
	r := h.do(t, http.MethodPost, "/payments/v1/query", pgQuery, nil)
	if r.refusal.Error != "kind_config_missing" || r.refusal.ErrorClass != "cannot_authorize" || r.refusal.Outcome != "" || len(h.auth.snap().begins) != 0 {
		t.Fatalf("%d %s", r.code, r.body)
	}
}

// TestHR330_PostgresPrivateTargetNeedsInternal: a loopback database the
// connection does not mark internal is refused at dial time, whatever the
// operator allows (D98).
func TestHR330_PostgresPrivateTargetNeedsInternal(t *testing.T) {
	tg := pgtargettest.New(t)
	h := setup(t, withPostgres(t, tg, false), func(h *harness) { h.conn.Postgres.Internal = false })
	r := h.do(t, http.MethodPost, "/payments/v1/query", pgQuery, nil)
	if r.refusal.Error != "egress_denied" {
		t.Fatalf("%d %s", r.code, r.body)
	}
}

func scopeObligations(customer string, classes ...string) []*pb.Obligation {
	var out []*pb.Obligation
	if customer != "" {
		out = append(out, &pb.Obligation{Kind: "record_scope", Param: "customer", Values: []string{customer}, Timing: "before_execution"})
	}
	if classes != nil {
		out = append(out, &pb.Obligation{Kind: "data_classes", Values: classes, Timing: "before_execution"})
	}
	return out
}

func pgRows(t *testing.T, h *harness, path, body string) (pgAnswer, reply) {
	t.Helper()
	r := h.do(t, http.MethodPost, path, body, nil)
	var a pgAnswer
	if r.code == http.StatusOK {
		if err := json.Unmarshal([]byte(r.body), &a); err != nil {
			t.Fatal(err)
		}
	}
	return a, r
}

// TestHR310_RecordScopeIsAMandatoryPredicate (D20): under a record scope
// only the scoped customer's rows come back, however the agent filters,
// sorts or aggregates; a table without that scope key is refused.
func TestHR310_RecordScopeIsAMandatoryPredicate(t *testing.T) {
	tg := pgtargettest.New(t)
	h := setup(t, withPostgres(t, tg, false), func(h *harness) { h.auth.obligations = scopeObligations("2") })
	a, r := pgRows(t, h, "/payments/v1/query", `{"table":"shop.orders","columns":["id","customer_id"]}`)
	if r.code != http.StatusOK || len(a.Rows) != 3 {
		t.Fatalf("scoped rows: %d %s", r.code, r.body)
	}
	for _, row := range a.Rows {
		if row[1] != float64(2) {
			t.Fatalf("another customer's row %v", row)
		}
	}
	// The receipt records counts only (D20, D102).
	recs := h.auth.snap().records
	if ds := recs[len(recs)-1].GetDataScope(); ds.GetRecordsKey() != "customer" || ds.GetRows() != 3 || ds.GetValuesRedacted() != 0 {
		t.Fatalf("data scope on the record: %v", ds)
	}
	// Asking for another customer finds nothing.
	a, _ = pgRows(t, h, "/payments/v1/query", `{"table":"shop.orders","columns":["id"],"filters":[{"column":"customer_id","op":"eq","value":"1"}]}`)
	if len(a.Rows) != 0 {
		t.Fatalf("escaped by filter: %v", a.Rows)
	}
	a, _ = pgRows(t, h, "/payments/v1/query", `{"table":"shop.customers","columns":["id","tier"]}`)
	if len(a.Rows) != 1 || a.Rows[0][0] != float64(2) {
		t.Fatalf("customers: %v", a.Rows)
	}
	// The scoped customer has 3 orders: under the minimum group size.
	a, r = pgRows(t, h, "/payments/v1/aggregate", `{"table":"shop.orders","measures":["count:*"]}`)
	if r.code != http.StatusOK || len(a.Rows) != 0 {
		t.Fatalf("aggregate: %d %s", r.code, r.body)
	}
}

// TestHR311_ClassesThroughTheGateway (D20): under a data_classes scope the
// values of other classes come back withheld and cannot be filtered,
// sorted or grouped on; secret never comes back; count still counts.
func TestHR311_ClassesThroughTheGateway(t *testing.T) {
	tg := pgtargettest.New(t)
	h := setup(t, withPostgres(t, tg, false), func(h *harness) { h.auth.obligations = scopeObligations("", "public") })
	a, r := pgRows(t, h, "/payments/v1/query", pgQuery)
	if r.code != http.StatusOK || a.Rows[0][1] != "[redacted:pii]" || a.Rows[0][2] != "[redacted:secret]" || strings.Contains(r.body, "@example.com") {
		t.Fatalf("redacted: %d %s", r.code, r.body)
	}
	recs := h.auth.snap().records
	if ds := recs[len(recs)-1].GetDataScope(); ds.GetRecordsKey() != "" || ds.GetRows() != 2 || ds.GetValuesRedacted() != 4 {
		t.Fatalf("data scope on the record: %v", ds)
	}
	for body, code := range map[string]string{
		`{"table":"shop.customers","columns":["id"],"filters":[{"column":"email","op":"prefix","value":"a"}]}`: "column_not_allowed",
		`{"table":"shop.customers","columns":["id"],"order_by":["name:asc"]}`:                                  "column_not_allowed",
	} {
		if _, r := pgRows(t, h, "/payments/v1/query", body); r.refusal.Error != code {
			t.Errorf("%s: %d %s", body, r.code, r.body)
		}
	}
	if _, r := pgRows(t, h, "/payments/v1/aggregate", `{"table":"shop.orders","group_by":["amount"],"measures":["count:*"]}`); r.refusal.Error != "column_not_allowed" {
		t.Errorf("group on internal: %d %s", r.code, r.body)
	}
	a, r = pgRows(t, h, "/payments/v1/aggregate", `{"table":"shop.orders","measures":["count:amount"]}`)
	if r.code != http.StatusOK || len(a.Rows) != 1 || a.Rows[0][0] != float64(11) {
		t.Errorf("count of an internal column: %d %s", r.code, r.body)
	}
}

// TestT143_InjectionAndWritesThroughTheFaces: hostile identifiers and
// values through either face never become SQL, and a write-capable role
// never runs a query.
func TestT143_InjectionAndWritesThroughTheFaces(t *testing.T) {
	tg := pgtargettest.New(t)
	h := setup(t, withPostgres(t, tg, false))
	for _, body := range []string{
		`{"table":"shop.orders; DELETE FROM shop.orders","columns":["id"]}`,
		`{"table":"shop.orders","columns":["id\"; DROP TABLE shop.orders; --"]}`,
		`{"table":"shop.orders","columns":["id"],"order_by":["id:asc, (SELECT pg_sleep(5))"]}`,
	} {
		if r := h.do(t, http.MethodPost, "/payments/v1/query", body, nil); r.code == http.StatusOK {
			t.Errorf("%s answered %s", body, r.body)
		}
	}
	a, r := pgRows(t, h, "/payments/v1/query", `{"table":"shop.orders","columns":["id"],"filters":[{"column":"status","op":"prefix","value":"%' OR '1'='1"}]}`)
	if r.code != http.StatusOK || len(a.Rows) != 0 {
		t.Fatalf("prefix injection: %d %s", r.code, r.body)
	}
	a, _ = pgRows(t, h, "/payments/v1/aggregate", `{"table":"shop.orders","measures":["count:*"]}`)
	if len(a.Rows) != 1 || a.Rows[0][0] != float64(11) {
		t.Fatalf("orders changed: %v", a.Rows)
	}
	w := setup(t, withPostgres(t, tg, true))
	if r := w.do(t, http.MethodPost, "/payments/v1/query", pgQuery, nil); r.refusal.Error != "role_not_read_only" {
		t.Fatalf("writer: %s", r.body)
	}
}

// TestT144_ScopeEscapeAttemptsAtTheGateway: under a record scope and a
// public-only class scope, sorting or grouping on a secret column, a
// filter on another customer and a table outside the scope key all fail
// to reveal anything.
func TestT144_ScopeEscapeAttemptsAtTheGateway(t *testing.T) {
	tg := pgtargettest.New(t)
	tg.AdminExec(t, "CREATE TABLE shop.notes (id bigint, body text)", "GRANT SELECT ON shop.notes TO "+tg.ReadOnly)
	h := setup(t, withPostgres(t, tg, false), func(h *harness) {
		h.auth.obligations = scopeObligations("1", "public")
		h.conn.Postgres.Tables = append(h.conn.Postgres.Tables, &pb.PostgresTable{Schema: "shop", Name: "notes", Columns: []*pb.PostgresColumn{
			{Name: "id", Type: "bigint", Class: "public"}, {Name: "body", Type: "text", Class: "internal"},
		}})
	})
	for path, body := range map[string]string{
		"/payments/v1/query":     `{"table":"shop.customers","columns":["id"],"order_by":["ssn:desc"]}`,
		"/payments/v1/aggregate": `{"table":"shop.customers","group_by":["ssn"],"measures":["count:*"]}`,
	} {
		if _, r := pgRows(t, h, path, body); r.refusal.Error != "column_not_allowed" {
			t.Errorf("%s: %d %s", body, r.code, r.body)
		}
	}
	if _, r := pgRows(t, h, "/payments/v1/query", `{"table":"shop.notes","columns":["id"]}`); r.refusal.Error != "scope_unsupported" {
		t.Errorf("table without the scope key: %d %s", r.code, r.body)
	}
	a, _ := pgRows(t, h, "/payments/v1/query", `{"table":"shop.customers","columns":["id","ssn"],"filters":[{"column":"id","op":"in","values":["2","3"]}]}`)
	if len(a.Rows) != 0 {
		t.Fatalf("another customer: %v", a.Rows)
	}
}

// TestHR301_PostgresPatternPerDefinition (D105): a definition's credential
// pattern is checked on its own dispatch, even when the pool is already
// open for another definition.
func TestHR301_PostgresPatternPerDefinition(t *testing.T) {
	tg := pgtargettest.New(t)
	h := setup(t, withPostgres(t, tg, false), func(h *harness) {
		h.mutatePkg = func(raw []byte) []byte {
			return []byte(strings.Replace(string(raw), "    dispatch:\n      sql:\n        operation: rows\n",
				"    dispatch:\n      credential_pattern: '^nothing-matches$'\n      sql:\n        operation: rows\n", 1))
		}
	})
	if _, r := pgRows(t, h, "/payments/v1/aggregate", `{"table":"shop.orders","measures":["count:*"]}`); r.code != http.StatusOK {
		t.Fatalf("aggregate: %d %s", r.code, r.body)
	}
	if _, r := pgRows(t, h, "/payments/v1/query", pgQuery); r.code == http.StatusOK || !strings.Contains(r.refusal.Error, "credential") {
		t.Fatalf("patterned read: %d %s", r.code, r.body)
	}
}
