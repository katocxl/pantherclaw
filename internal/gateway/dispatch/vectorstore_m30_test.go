// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pcvectorstore "github.com/katocxl/pantherclaw/packages/pc-vectorstore"
)

func vecConfig() *pb.VectorstoreConfig {
	return &pb.VectorstoreConfig{SchemaName: "rag", TableName: "docs", Dimensions: 3, Distance: "cosine"}
}

func vecPackage(t *testing.T) *defs.Package {
	t.Helper()
	pkg, err := manifest.Decode(pcvectorstore.Package)
	if err != nil {
		t.Fatal(err)
	}
	return pkg
}

// vecAction is a permitted pc.vectorstore action on table with params, as
// the gateway holds it after the permit.
func vecAction(t *testing.T, op, table, params string) (*defs.Definition, actionir.ActionIR) {
	t.Helper()
	def, ok := vecPackage(t).Definition(op)
	if !ok {
		t.Fatalf("no %s", op)
	}
	return def, actionir.ActionIR{Operation: op, Target: actionir.Target{Type: "vector_table", ID: table}, Params: jsontext.Value(params)}
}

// vecMapMCP maps one MCP tool call of pc.vectorstore.
func vecMapMCP(t *testing.T, tool, args string) error {
	t.Helper()
	m, err := mapping.New(vecPackage(t), celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.MCP(context.Background(), pgContext(), tool, []byte(args))
	return err
}

// e123 and e05 are canonical float_array strings, as an ActionIR holds
// them (G0 M30 D1211).
var (
	e123 = mustCanon(1, 2, 3)
	e05  = mustCanon(0.5, 0.25, 1)
)

var upsertParams = `{"id":"doc-1","content":"refunds take 5 days","embedding":` + e05 + `,"metadata":{"source":"wiki"}}`

func provenance() permitWant {
	return permitWant{Txn: ids.NewV7().String(), Run: ids.NewV7().String(), Agent: ids.NewV7().String()}
}

// TestHR704_ProvenanceComesFromThePermit: a write binds the permit's run,
// agent and transaction as its pc_* values, and the SQL holds no value the
// agent sent (G0 M30 D923, D923a).
func TestHR704_ProvenanceComesFromThePermit(t *testing.T) {
	def, a := vecAction(t, "vectorstore.records.upsert", "rag.docs", upsertParams)
	want := provenance()
	st, write, err := vecStatement(vecConfig(), def, a, want)
	if err != nil || !write {
		t.Fatalf("write %v err %v", write, err)
	}
	if strings.Contains(st.SQL, "refunds") || strings.Contains(st.SQL, "wiki") || !strings.Contains(st.SQL, "$3::vector") {
		t.Fatalf("SQL %s", st.SQL)
	}
	got := st.Args[len(st.Args)-3:]
	if got[0] != want.Run || got[1] != want.Agent || got[2] != want.Txn || st.Args[2] != "[0.5,0.25,1]" {
		t.Fatalf("args %v, want provenance %s %s %s", st.Args, want.Run, want.Agent, want.Txn)
	}
}

// TestHR704_WithoutPermitProvenanceOrOverBoundsNothingIsBuilt: a write
// whose permit lacks the run or agent fails closed; an agent cannot send a
// pc_* column (the schema is closed); content over 8 KiB, a bad metadata
// key and too many filter keys are refused.
func TestHR704_WithoutPermitProvenanceOrOverBoundsNothingIsBuilt(t *testing.T) {
	def, a := vecAction(t, "vectorstore.records.upsert", "rag.docs", upsertParams)
	full := provenance()
	for name, want := range map[string]permitWant{
		"no run":   {Txn: full.Txn, Agent: full.Agent},
		"no agent": {Txn: full.Txn, Run: full.Run},
	} {
		if _, _, err := vecStatement(vecConfig(), def, a, want); !errors.Is(err, errProvenanceMissing) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, params := range map[string]string{
		"pc column":      `{"id":"x","content":"c","embedding":` + e123 + `,"pc_run_id":"` + ids.NewV7().String() + `"}`,
		"content > 8KiB": `{"id":"x","content":"` + strings.Repeat("a", 8<<10+1) + `","embedding":` + e123 + `}`,
		"metadata key":   `{"id":"x","content":"c","embedding":` + e123 + `,"metadata":{"bad key":"v"}}`,
		"number list":    `{"id":"x","content":"c","embedding":[1,2,3]}`,
	} {
		def, a := vecAction(t, "vectorstore.records.upsert", "rag.docs", params)
		if _, _, err := vecStatement(vecConfig(), def, a, full); err == nil {
			t.Errorf("%s: built", name)
		}
	}
	var keys []string
	for i := range 17 {
		keys = append(keys, `"k`+string(rune('a'+i))+`":"v"`)
	}
	def, a = vecAction(t, "vectorstore.records.query", "rag.docs", `{"embedding":`+e123+`,"filter":{`+strings.Join(keys, ",")+`}}`)
	if _, _, err := vecStatement(vecConfig(), def, a, permitWant{}); err == nil {
		t.Error("17 filter keys built")
	}
	// The tool's schema is closed: a pc_* argument is refused where the same
	// call without it maps.
	if err := vecMapMCP(t, "vector_delete", `{"table":"rag.docs","id":"x"}`); err != nil {
		t.Fatal(err)
	}
	if err := vecMapMCP(t, "vector_delete", `{"table":"rag.docs","id":"x","pc_agent_id":"`+ids.NewV7().String()+`"}`); err == nil {
		t.Error("a pc_* argument mapped")
	}
}

// TestT322_ReadersSeeProvenanceAndOtherTablesBuildNothing: a query returns
// the provenance columns, and a write naming a table other than the
// connection's builds nothing.
func TestT322_ReadersSeeProvenanceAndOtherTablesBuildNothing(t *testing.T) {
	def, a := vecAction(t, "vectorstore.records.query", "rag.docs", `{"embedding":`+e123+`,"top_k":"5"}`)
	st, write, err := vecStatement(vecConfig(), def, a, permitWant{})
	if err != nil || write || !strings.Contains(st.SQL, `"pc_run_id"`) || !strings.Contains(st.SQL, `"pc_agent_id"`) ||
		!strings.Contains(st.SQL, "<=>") {
		t.Fatalf("query %v %v %+v", write, err, st)
	}
	def, a = vecAction(t, "vectorstore.records.upsert", "rag.other", upsertParams)
	if _, _, err := vecStatement(vecConfig(), def, a, provenance()); err == nil {
		t.Fatal("another table built a statement")
	}
}

// mustCanon is the quoted canonical float_array string of fs.
func mustCanon(fs ...float64) string {
	s, err := defs.EncodeFloat32s(fs)
	if err != nil {
		panic(err)
	}
	return `"` + s + `"`
}

// TestHR704_EmbeddingsMapThroughEitherFace (G0 M30 D1211): vector_query and
// vector_upsert map from MCP and HTTP with the embedding as JSON numbers;
// both faces give one action whose embedding is the canonical string, which
// the dispatch binds as the vector literal.
func TestHR704_EmbeddingsMapThroughEitherFace(t *testing.T) {
	m, err := mapping.New(vecPackage(t), celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ tool, path, body, vector string }{
		{"vector_query", "/v1/vector/query", `{"table":"rag.docs","embedding":[0.5,0.25,1],"top_k":3}`, "[0.5,0.25,1]"},
		{"vector_upsert", "/v1/vector/upsert", `{"table":"rag.docs","id":"doc-1","content":"c","embedding":[1,-2.5e-1,3]}`, "[1,-0.25,3]"},
	} {
		ctx := pgContext()
		viaMCP, err := m.MCP(context.Background(), ctx, tc.tool, []byte(tc.body))
		if err != nil {
			t.Fatalf("%s over MCP: %v", tc.tool, err)
		}
		viaHTTP, err := m.HTTPRequest(context.Background(), ctx, "POST", tc.path, "", "application/json", []byte(tc.body))
		if err != nil {
			t.Fatalf("%s over HTTP: %v", tc.tool, err)
		}
		if string(viaMCP.Action.Params) != string(viaHTTP.Action.Params) || strings.Contains(string(viaMCP.Action.Params), "[") {
			t.Fatalf("%s: params %s and %s", tc.tool, viaMCP.Action.Params, viaHTTP.Action.Params)
		}
		def, _ := vecPackage(t).Definition(viaMCP.Action.Operation)
		st, _, err := vecStatement(vecConfig(), def, viaMCP.Action, provenance())
		if err != nil || !slices.Contains(st.Args, any(tc.vector)) {
			t.Fatalf("%s: statement %+v %v, want the vector %s", tc.tool, st, err, tc.vector)
		}
	}
}

// TestHR704_NumbersOnlyWhereAFloatArrayIsExtracted (G0 M30 D1211, HR-101):
// a number anywhere else, and an embedding with NaN-like text, an infinity,
// a float32 overflow, too many items, a string item, no items or a nested
// list, each refuse the call as ambiguous.
func TestHR704_NumbersOnlyWhereAFloatArrayIsExtracted(t *testing.T) {
	big := strings.Repeat("1,", defs.MaxFloatItems) + "1"
	for name, body := range map[string]string{
		"number as id":       `{"table":"rag.docs","id":7,"content":"c","embedding":[1,2,3]}`,
		"float in metadata":  `{"table":"rag.docs","id":"x","content":"c","embedding":[1,2,3],"metadata":{"k":1.5}}`,
		"NaN":                `{"table":"rag.docs","id":"x","content":"c","embedding":[NaN,2,3]}`,
		"infinity text":      `{"table":"rag.docs","id":"x","content":"c","embedding":[1e999,2,3]}`,
		"float32 overflow":   `{"table":"rag.docs","id":"x","content":"c","embedding":[3.5e38,2,3]}`,
		"too many items":     `{"table":"rag.docs","id":"x","content":"c","embedding":[` + big + `]}`,
		"string item":        `{"table":"rag.docs","id":"x","content":"c","embedding":["1",2,3]}`,
		"no items":           `{"table":"rag.docs","id":"x","content":"c","embedding":[]}`,
		"nested list":        `{"table":"rag.docs","id":"x","content":"c","embedding":[[1],2,3]}`,
		"canonical as input": `{"table":"rag.docs","id":"x","content":"c","embedding":` + e123 + `}`,
	} {
		if err := vecMapMCP(t, "vector_upsert", body); !errors.Is(err, actionir.ErrAmbiguous) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The same call with a whole-number embedding maps, and so does one of
	// the most items, whose canonical string is exactly 64 KiB (D1213).
	if err := vecMapMCP(t, "vector_upsert", `{"table":"rag.docs","id":"x","content":"c","embedding":[1,2,3]}`); err != nil {
		t.Fatal(err)
	}
	most := strings.Repeat("-0.5,", defs.MaxFloatItems-1) + "3.4e38"
	if err := vecMapMCP(t, "vector_upsert", `{"table":"rag.docs","id":"x","content":"c","embedding":[`+most+`]}`); err != nil {
		t.Fatalf("%d items: %v", defs.MaxFloatItems, err)
	}
}
