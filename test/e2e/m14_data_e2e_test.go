// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"io"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	connapp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/connections/pgmanifest"
	credapp "github.com/katocxl/pantherclaw/internal/credentials/app"
	creddomain "github.com/katocxl/pantherclaw/internal/credentials/domain"
	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/gateway"
	"github.com/katocxl/pantherclaw/internal/gateway/pgtarget/pgtargettest"
	grantspg "github.com/katocxl/pantherclaw/internal/grants/adapters/pgstore"
	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/grants/grantstest"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	runsapp "github.com/katocxl/pantherclaw/internal/runs/app"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The read-only Postgres connector and data scoping of G0 M14 end to end
// (PN-017.4, F101–F103; D15–D21): dev seed points the connection
// "warehouse" at the D19 fixture database behind a TLS proxy, a gateway
// admin seals the read-only role's password and confirms the manifest with
// a security key, and a grant limited to one customer's records and to
// public data reads it through the gateway's HTTP and MCP faces.

// pgSeed is the stack's fixture database and its connection.
type pgSeed struct {
	tg   *pgtargettest.Target
	conn ids.UUID
	gw   ids.UUID
}

var seededPostgres = regexp.MustCompile(`seeded postgres connection ([0-9a-f-]{36}) `)

// postgresSeedFile writes the CA and the URL dev seed --postgres reads.
func (s *stack) postgresSeedFile(t *testing.T, dir string, tg *pgtargettest.Target) string {
	t.Helper()
	ca := writeFile(t, dir, "pg-ca.pem", []byte(tg.CAPEM))
	return writeFile(t, dir, "pg.url", []byte(tg.URL(filepath.ToSlash(ca))))
}

// postgresSeeded reads the seeded connection from dev seed's output.
func (s *stack) postgresSeeded(t *testing.T, out string, tg *pgtargettest.Target) {
	t.Helper()
	m := seededPostgres.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("dev seed output %q", out)
	}
	s.pg = &pgSeed{tg: tg, conn: mustUUID(t, m[1])}
}

// postgresReady seals the read-only role's password as a gateway admin
// does with pclaw seal (no header: D84) and confirms the proposed manifest
// with a security key (D84, D92); the gateway then serves it.
func (s *stack) postgresReady(t *testing.T) {
	t.Helper()
	s.sealPostgres(t, s.pg.tg.ReadOnlyPass)
	admin := s.person(t, "pg-admin-"+ids.NewV7().String()[24:], td.RoleGatewayAdmin)
	svc := pgmanifest.New(s.pool)
	m, err := svc.Get(admin.ctx, s.pg.conn)
	if err != nil || m.Proposed == nil || m.Current != nil {
		t.Fatalf("proposed manifest: %+v %v", m, err)
	}
	if err := svc.Confirm(admin.ctx, s.pg.conn, m.Digest, &stepup.StepUp{Credential: admin.key, At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	s.waitConfig(t, s.configVersion(t, s.pg.gw))
}

// sealPostgres seals password for the warehouse connection.
func (s *stack) sealPostgres(t *testing.T, password string) {
	t.Helper()
	admin := s.person(t, "pg-sealer-"+ids.NewV7().String()[24:], td.RoleGatewayAdmin)
	svc := credapp.New(s.pool, nil)
	k, err := svc.GetSealingKey(admin.ctx, s.pg.conn)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := pccrypto.ParseSealPublicKey(k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := pccrypto.Seal(pub, k.Binding.Info(), creddomain.AAD, []byte(password))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.PutCredential(admin.ctx, credapp.PutInput{
		Connection: s.pg.conn, BrokerKey: mustUUID(t, k.Binding.BrokerKey), Version: k.Binding.Version, Sealed: sealed,
		AllowedHosts: k.Binding.AllowedHosts, Header: k.Binding.Header, Scheme: k.Binding.Scheme,
	}); err != nil {
		t.Fatal(err)
	}
	s.pg.gw = k.Gateway
	s.waitConfig(t, s.configVersion(t, k.Gateway))
}

// scopedRun issues the seeded agent a grant for the postgres reads with
// this data scope (Team, D11), starts a run on it, and makes it the
// stack's run.
func (s *stack) scopedRun(t *testing.T, scope string) {
	t.Helper()
	s.grantRun(t, `{"operations": ["postgres.rows.read", "postgres.rows.aggregate", "postgres.tables.read"],
	  "params": {"postgres.rows.read": {"columns": {"values": {"ids": ["id", "customer_id", "name", "email", "tier", "ssn", "amount", "status", "subject"]}}}},
	  "scope": `+scope+`}`, true)
}

// grantRun issues the seeded agent a grant with these bounds, the Team
// edition when team, starts a run on it and makes it the stack's run.
func (s *stack) grantRun(t *testing.T, bounds string, team bool) {
	t.Helper()
	var agent, inst string
	s.query(t, "SELECT agent_id::text FROM pc.runs WHERE id = $1", []any{s.run}, &agent)
	s.query(t, "SELECT id::text FROM pc.agent_instances WHERE agent_id = $1 AND state = 'ADMITTED' LIMIT 1", []any{agent}, &inst)
	user := ids.NewV7()
	s.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)", s.org, user, "issuer-"+user.String()[24:])
	human := tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
		Org: s.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: user},
		Bindings: []td.Binding{
			{Role: td.RoleOrgAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: s.org.UUID()}},
			{Role: td.RoleRunLauncher, Scope: td.Scope{Type: td.ScopeOrg, ID: s.org.UUID()}},
		},
	}, Credential: tapp.CredAccessToken})
	b, err := gdomain.DecodeBounds([]byte(bounds))
	if err != nil {
		t.Fatal(err)
	}
	gs := &grantspg.Store{Pool: s.pool, Promotions: grantstest.OpenGate{}}
	grants := &grantsapp.Service{Repo: gs, Subjects: gs, Defs: &defspg.Store{Pool: s.pool}, Authz: allowAll{}, Clock: clock.System{}}
	if team {
		grants.Editions = teamEdition{}
	}
	g, err := grants.Issue(human, grantsapp.IssueRequest{
		AgentID: mustUUID(t, agent), Principal: gdomain.Principal{Kind: gdomain.PrincipalUser, ID: user}, TaskRef: "data",
		ExpiresAt: time.Now().Add(time.Hour), Bounds: b,
	})
	if err != nil {
		t.Fatal(err)
	}
	instance, grant := mustUUID(t, inst), g.ID.UUID()
	run, err := runsapp.New(s.pool).WithGrants(gs).StartRun(human, runsapp.StartInput{
		AgentID: mustUUID(t, agent), InstanceID: &instance, GrantID: &grant, TaskRef: "data",
	})
	if err != nil {
		t.Fatal(err)
	}
	s.run = run.ID.String()
}

// pgAnswer is a postgres read's answer.
type pgAnswer struct {
	Columns   []string `json:"columns"`
	Rows      [][]any  `json:"rows"`
	Truncated bool     `json:"truncated"`
	Redacted  int      `json:"redacted"`
}

// pgCall sends one read through the warehouse connection's HTTP face as
// the seeded workload.
func (s *stack) pgCall(t *testing.T, method, path, body string) (int, reply, pgAnswer) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, _ := http.NewRequestWithContext(context.Background(), method, s.gateway+"/warehouse"+path, rd)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set(gateway.HeaderRunID, s.run)
	req.Header.Set(gateway.HeaderActionID, ids.NewV7().String())
	client := &http.Client{Timeout: 30 * time.Second, Transport: &workloadclient.Transport{
		Key: s.key, Token: func() string { return s.token }, Base: http.DefaultTransport,
	}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	var r reply
	var a pgAnswer
	if resp.StatusCode >= 300 {
		_ = json.Unmarshal(b, &r)
	} else if err := json.Unmarshal(b, &a); err != nil {
		t.Fatalf("answer %s: %v", b, err)
	}
	return resp.StatusCode, r, a
}

// pgTool calls a warehouse MCP tool as the seeded workload and returns its
// structured content, or the tool error's text.
func (s *stack) pgTool(t *testing.T, tool, args string) (pgAnswer, string) {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",` +
		`"io.modelcontextprotocol/clientCapabilities":{}},"name":"` + tool + `","arguments":` + args + `}}`
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, s.gateway+"/mcp/warehouse", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2026-07-28")
	req.Header.Set("Mcp-Method", "tools/call")
	req.Header.Set("Mcp-Name", tool)
	req.Header.Set(gateway.HeaderRunID, s.run)
	client := &http.Client{Timeout: 30 * time.Second, Transport: &workloadclient.Transport{
		Key: s.key, Token: func() string { return s.token }, Base: http.DefaultTransport,
	}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	var out struct {
		Result struct {
			IsError           bool           `json:"isError"`
			StructuredContent jsontext.Value `json:"structuredContent"`
			Content           []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("mcp %d %s: %v", resp.StatusCode, b, err)
	}
	if out.Result.IsError {
		return pgAnswer{}, out.Result.Content[0].Text
	}
	var a pgAnswer
	if err := json.Unmarshal(out.Result.StructuredContent, &a); err != nil {
		t.Fatalf("structured %s: %v", out.Result.StructuredContent, err)
	}
	return a, ""
}

// connectionTest runs a postgres connection's read test (D18) and waits
// for the gateway's result.
func (s *stack) connectionTest(t *testing.T) string {
	t.Helper()
	admin := s.person(t, "pg-tester-"+ids.NewV7().String()[24:], td.RoleGatewayAdmin)
	svc := connapp.New(s.pool, nil, s.apiURL, "")
	r, err := svc.Test(admin.ctx, s.pg.conn, connapp.KindReadTest)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		var state, result string
		s.query(t, "SELECT state, coalesce(result, '') FROM pc.connection_tests WHERE id = $1", []any{r.ID}, &state, &result)
		if state == "DONE" || state == "FAILED" {
			return result
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("the connection test did not finish")
	return ""
}

// TestE2E_M14_DataScoping is D21's scenario on the Community stack (D109):
// the connection test passes a read-only role; a grant bounding the
// columns and capping the rows reads through the HTTP and MCP faces alike;
// a column outside the bound and a request over the cap are DENY, secret
// values never leave the database, a crafted value writes nothing, a lock
// wait fails without hanging, and a role that could write fails the
// connection test and reads nothing.
func TestE2E_M14_DataScoping(t *testing.T) {
	tg := pgtargettest.New(t)
	s := start(t, options{budget: "1000.00", postgres: tg})
	if res := s.connectionTest(t); res != "PASSED" {
		t.Fatalf("connection test: %q", res)
	}
	s.grantRun(t, `{"operations": ["postgres.rows.read", "postgres.rows.aggregate", "postgres.tables.read"],
	  "params": {"postgres.rows.read": {"columns": {"values": {"ids": ["id", "customer_id", "tier", "ssn", "amount", "status"]}},
	    "limit": {"range": {"max": "2", "unit": "rows"}}}}}`, false)

	// Allowed columns are read; secret never leaves the database.
	code, r, a := s.pgCall(t, http.MethodPost, "/v1/query", `{"table":"shop.customers","columns":["id","tier","ssn"],"order_by":["id:asc"],"limit":2}`)
	if code != http.StatusOK || len(a.Rows) != 2 || a.Rows[0][1] != "gold" || a.Rows[0][2] != "[redacted:secret]" {
		t.Fatalf("read: %d %+v %+v", code, r, a)
	}
	// The MCP face gives the same answer (F099).
	m, errText := s.pgTool(t, "query_rows", `{"table":"shop.customers","columns":["id","tier","ssn"],"order_by":["id:asc"],"limit":2}`)
	if errText != "" || len(m.Rows) != 2 || m.Rows[1][0] != a.Rows[1][0] || m.Rows[0][2] != "[redacted:secret]" {
		t.Fatalf("mcp: %+v %s", m, errText)
	}
	// A column outside the grant's bound is a DENY (F105).
	if code, r, _ := s.pgCall(t, http.MethodPost, "/v1/query", `{"table":"shop.customers","columns":["id","email"]}`); code == http.StatusOK || r.Decision != "DENY" {
		t.Fatalf("column outside the bound: %d %+v", code, r)
	}
	// The grant caps the rows: a larger request is a DENY, and an answer at
	// the cap says more rows matched.
	if code, r, _ := s.pgCall(t, http.MethodPost, "/v1/query", `{"table":"shop.orders","columns":["id"],"limit":10}`); code == http.StatusOK || r.Decision != "DENY" {
		t.Fatalf("over the row cap: %d %+v", code, r)
	}
	if code, r, a := s.pgCall(t, http.MethodPost, "/v1/query", `{"table":"shop.orders","columns":["id"],"limit":2}`); code != http.StatusOK ||
		len(a.Rows) != 2 || !a.Truncated {
		t.Fatalf("at the row cap: %d %+v %+v", code, r, a)
	}
	// A crafted value runs as a parameter and writes nothing.
	if code, r, a := s.pgCall(t, http.MethodPost, "/v1/query",
		`{"table":"shop.orders","columns":["id"],"limit":2,"filters":[{"column":"status","op":"prefix","value":"x'; DELETE FROM shop.orders; --"}]}`); code != http.StatusOK || len(a.Rows) != 0 {
		t.Fatalf("crafted value: %d %+v %+v", code, r, a)
	}
	if code, r, a := s.pgCall(t, http.MethodPost, "/v1/aggregate", `{"table":"shop.orders","measures":["count:*"]}`); code != http.StatusOK ||
		len(a.Rows) != 1 || a.Rows[0][0] != float64(11) {
		t.Fatalf("orders after the crafted value: %d %+v %+v", code, r, a)
	}

	// A statement that waits on a lock fails, and does not hang.
	release := tg.Lock(t, "shop.customers")
	began := time.Now()
	code, r, _ = s.pgCall(t, http.MethodPost, "/v1/query", `{"table":"shop.customers","columns":["id"],"limit":1}`)
	release()
	if code == http.StatusOK || r.Error != "statement_timeout" || r.Outcome != "FAILED" || time.Since(began) > 15*time.Second {
		t.Fatalf("lock wait: %d %+v after %s", code, r, time.Since(began))
	}

	// A role that can write fails the connection test, and reads nothing.
	tg.AdminExec(t, "GRANT INSERT ON shop.orders TO "+tg.ReadOnly)
	if res := s.connectionTest(t); res != "FAILED" {
		t.Fatalf("write-capable role passed the test: %q", res)
	}
	if code, r, _ := s.pgCall(t, http.MethodPost, "/v1/query", `{"table":"shop.customers","columns":["id"],"limit":1}`); code == http.StatusOK || r.Error != "role_not_read_only" {
		t.Fatalf("write-capable role: %d %+v", code, r)
	}
}

// TestT144_DataScopeThroughTheStack drives F101 data scope (Team, D11)
// through the real Authority and the gateway's scope engine (D109): a
// grant limited to customer 2 and to public data sees only that
// customer's rows, pii and secret withheld, and no group under the
// minimum; with pii allowed the email shows, secret still never does.
func TestT144_DataScopeThroughTheStack(t *testing.T) {
	tg := pgtargettest.New(t)
	s := start(t, options{budget: "1000.00", postgres: tg})
	s.scopedRun(t, `{"postgres.rows.read": {"records": {"key": "customer", "values": ["2"]}, "classes": {"ids": ["public"]}},
	  "postgres.rows.aggregate": {"records": {"key": "customer", "values": ["2"]}, "classes": {"ids": ["public"]}}}`)
	code, r, a := s.pgCall(t, http.MethodPost, "/v1/query", `{"table":"shop.customers","columns":["id","tier","email","ssn"]}`)
	if code != http.StatusOK || len(a.Rows) != 1 || a.Rows[0][0] != float64(2) || a.Rows[0][1] != "silver" ||
		a.Rows[0][2] != "[redacted:pii]" || a.Rows[0][3] != "[redacted:secret]" {
		t.Fatalf("scoped read: %d %+v %+v", code, r, a)
	}
	m, errText := s.pgTool(t, "query_rows", `{"table":"shop.customers","columns":["id","tier","email","ssn"]}`)
	if errText != "" || len(m.Rows) != 1 || m.Rows[0][2] != "[redacted:pii]" {
		t.Fatalf("mcp: %+v %s", m, errText)
	}
	if _, _, a := s.pgCall(t, http.MethodPost, "/v1/query", `{"table":"shop.orders","columns":["id"],"filters":[{"column":"customer_id","op":"eq","value":"1"}]}`); len(a.Rows) != 0 {
		t.Fatalf("another customer's orders: %+v", a)
	}
	if code, r, _ := s.pgCall(t, http.MethodPost, "/v1/query", `{"table":"shop.customers","columns":["id"],"order_by":["email:asc"]}`); code == http.StatusOK || r.Error != "column_not_allowed" {
		t.Fatalf("sort on pii: %d %+v", code, r)
	}
	if code, r, a := s.pgCall(t, http.MethodPost, "/v1/aggregate", `{"table":"shop.orders","measures":["count:*"]}`); code != http.StatusOK || len(a.Rows) != 0 {
		t.Fatalf("small group: %d %+v %+v", code, r, a)
	}
	s.scopedRun(t, `{"postgres.rows.read": {"records": {"key": "customer", "values": ["2"]}, "classes": {"ids": ["public", "pii"]}}}`)
	if _, _, a := s.pgCall(t, http.MethodPost, "/v1/query", `{"table":"shop.customers","columns":["email","ssn"]}`); len(a.Rows) != 1 ||
		a.Rows[0][0] != "alan@example.com" || a.Rows[0][1] != "[redacted:secret]" {
		t.Fatalf("pii allowed: %+v", a)
	}
}
