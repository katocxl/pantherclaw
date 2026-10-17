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
