// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

type recordSearch struct {
	pantherclawv1connect.UnimplementedSearchServiceHandler
	find      *pantherclawv1.FindRequest
	ask       *pantherclawv1.AskRequest
	interpret *pantherclawv1.InterpretRequest
	search    *pantherclawv1.SearchRequest
	builtin   *pantherclawv1.RunBuiltinQueryRequest
	export    *pantherclawv1.ExportResultsRequest
}

func (r *recordSearch) Find(_ context.Context, req *pantherclawv1.FindRequest) (*pantherclawv1.FindResponse, error) {
	r.find = req
	return &pantherclawv1.FindResponse{Text: req.GetText()}, nil
}

func (r *recordSearch) Ask(_ context.Context, req *pantherclawv1.AskRequest) (*pantherclawv1.AskResponse, error) {
	r.ask = req
	return &pantherclawv1.AskResponse{Interpretation: &pantherclawv1.Interpretation{
		Question: req.GetQuestion(), UnknownWords: []string{"zulu"}, NeedsClarification: true,
	}}, nil
}

func (r *recordSearch) Interpret(_ context.Context, req *pantherclawv1.InterpretRequest) (*pantherclawv1.InterpretResponse, error) {
	r.interpret = req
	return &pantherclawv1.InterpretResponse{Interpretation: &pantherclawv1.Interpretation{Question: req.GetQuestion()}}, nil
}

func (r *recordSearch) Search(_ context.Context, req *pantherclawv1.SearchRequest) (*pantherclawv1.SearchResponse, error) {
	r.search = req
	return &pantherclawv1.SearchResponse{Result: &pantherclawv1.SearchResult{}}, nil
}

func (r *recordSearch) RunBuiltinQuery(_ context.Context, req *pantherclawv1.RunBuiltinQueryRequest) (*pantherclawv1.RunBuiltinQueryResponse, error) {
	r.builtin = req
	return &pantherclawv1.RunBuiltinQueryResponse{Result: &pantherclawv1.SearchResult{}}, nil
}

func (r *recordSearch) ExportResults(_ context.Context, req *pantherclawv1.ExportResultsRequest) (*pantherclawv1.ExportResultsResponse, error) {
	r.export = req
	return &pantherclawv1.ExportResultsResponse{Format: req.GetFormat(), Data: []byte("entity,id\n"), Rows: 0,
		AsOfTime: timestamppb.Now(), AuditEntryId: "a-1", ScopePermission: "evidence.read"}, nil
}

// TestSearchCommands: pclaw search sends the text, question, query,
// built-in parameters and export source it is given, and an export writes
// the rows to the file and its scope and audit entry to stderr.
func TestSearchCommands(t *testing.T) {
	rs := &recordSearch{}
	cs := connect.NewServer()
	pantherclawv1connect.RegisterSearchServiceHandler(cs, rs)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	env := envOf(map[string]string{"PANTHERCLAW_SERVER": ts.URL, "PANTHERCLAW_API_KEY": "pck_test_x"})

	if code, _, errs := run(t, env, "search", "find", "deploy", "--kind", "agents", "--kind", "connections", "--limit", "3"); code != 0 ||
		rs.find.GetText() != "deploy" || len(rs.find.GetKinds()) != 2 || rs.find.GetLimit() != 3 {
		t.Fatalf("find: %d %s %+v", code, errs, rs.find)
	}
	code, out, errs := run(t, env, "search", "ask", "denied actions by zulu", "--tz", "Europe/London")
	if code != 0 || rs.ask.GetQuestion() != "denied actions by zulu" || rs.ask.GetTimezone() != "Europe/London" ||
		!strings.Contains(out, `"needsClarification":`) || !strings.Contains(out, "zulu") {
		t.Fatalf("ask: %d %s %s", code, errs, out)
	}
	if code, _, errs := run(t, env, "search", "ask", "unused grants", "--explain"); code != 0 || rs.interpret.GetQuestion() != "unused grants" {
		t.Fatalf("ask --explain: %d %s", code, errs)
	}
	if code, _, errs := run(t, env, "search", "run", "alerts", "--filters", `{"severities":["HIGH"]}`); code != 0 ||
		rs.search.GetQuery().GetEntity() != "alerts" || rs.search.GetQuery().GetFilters().GetSeverities()[0] != "HIGH" {
		t.Fatalf("run: %d %s", code, errs)
	}
	const inc = "0192aaaa-bbbb-7ccc-8ddd-000000000001"
	if code, _, errs := run(t, env, "search", "builtin", "incident_correlation", "--params", `{"incidentId":"`+inc+`","days":7}`); code != 0 ||
		rs.builtin.GetQuery().GetParams().GetIncidentId() != inc || rs.builtin.GetQuery().GetParams().GetDays() != 7 {
		t.Fatalf("builtin: %d %s", code, errs)
	}
	file := filepath.Join(t.TempDir(), "out.csv")
	code, _, errs = run(t, env, "search", "export", "--saved", inc, "--format", "csv", "--out", file)
	if code != 0 || rs.export.GetSource().GetSavedQueryId() != inc || rs.export.GetFormat() != "CSV" ||
		!strings.Contains(errs, "audit entry a-1") {
		t.Fatalf("export: %d %s %+v", code, errs, rs.export)
	}
	if b, err := os.ReadFile(file); err != nil || string(b) != "entity,id\n" {
		t.Fatalf("export file: %q %v", b, err)
	}
	if code, _, _ := run(t, env, "search", "export", "--saved", inc, "--query", `{"entity":"runs"}`); code == 0 {
		t.Fatal("two sources accepted")
	}
}
