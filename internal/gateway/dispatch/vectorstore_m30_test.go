// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"encoding/json/jsontext"
	"errors"
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

const upsertParams = `{"id":"doc-1","content":"refunds take 5 days","embedding":[0.5,0.25,1],"metadata":{"source":"wiki"}}`

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
		"pc column":      `{"id":"x","content":"c","embedding":[1,2,3],"pc_run_id":"` + ids.NewV7().String() + `"}`,
		"content > 8KiB": `{"id":"x","content":"` + strings.Repeat("a", 8<<10+1) + `","embedding":[1,2,3]}`,
		"metadata key":   `{"id":"x","content":"c","embedding":[1,2,3],"metadata":{"bad key":"v"}}`,
		"NaN-free list":  `{"id":"x","content":"c","embedding":["1",2,3]}`,
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
	def, a = vecAction(t, "vectorstore.records.query", "rag.docs", `{"embedding":[1,2,3],"filter":{`+strings.Join(keys, ",")+`}}`)
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
	def, a := vecAction(t, "vectorstore.records.query", "rag.docs", `{"embedding":[1,2,3],"top_k":"5"}`)
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
