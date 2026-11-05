// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline

import (
	"testing"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pcvectorstore "github.com/katocxl/pantherclaw/packages/pc-vectorstore"
)

// vectorDef is a pc.vectorstore definition by operation.
func vectorDef(t *testing.T, op string) *defs.Definition {
	t.Helper()
	pkg, err := manifest.Decode(pcvectorstore.Package)
	if err != nil {
		t.Fatal(err)
	}
	d, ok := pkg.Definition(op)
	if !ok {
		t.Fatalf("no %s", op)
	}
	return d
}

// runWriterHold runs the writer step for agent on a vectorstore connection
// whose writers are writers.
func runWriterHold(def *defs.Definition, agent ids.UUID, run bool, writers ...ids.UUID) *state {
	s := &state{ev: &Evaluation{}, def: def, conn: &Connection{Kind: "vectorstore", Writers: writers}}
	if run {
		s.run = &Run{AgentID: agent}
	}
	s.vectorWriterHold()
	return s
}

// TestHR705_WritersAndReadsAddNoHold: an upsert or delete by a listed
// writer, and any query, add nothing (G0 M30 D924).
func TestHR705_WritersAndReadsAddNoHold(t *testing.T) {
	writer := ids.NewV7()
	for name, s := range map[string]*state{
		"writer upsert": runWriterHold(vectorDef(t, "vectorstore.records.upsert"), writer, true, writer),
		"writer delete": runWriterHold(vectorDef(t, "vectorstore.records.delete"), writer, true, writer),
		"query":         runWriterHold(vectorDef(t, "vectorstore.records.query"), ids.NewV7(), true, writer),
	} {
		if len(s.cl.items) != 0 || len(s.ev.Approvals) != 0 {
			t.Errorf("%s: %+v %+v", name, s.cl.items, s.ev.Approvals)
		}
	}
}

// TestHR705_ANonWriterWriteHolds: an upsert or delete by an agent not on
// the list, with an empty list, or with no known run, waits for a person
// (VECTOR_WRITE_NOT_WRITER); the step never allows.
func TestHR705_ANonWriterWriteHolds(t *testing.T) {
	writer := ids.NewV7()
	for name, s := range map[string]*state{
		"other agent": runWriterHold(vectorDef(t, "vectorstore.records.upsert"), ids.NewV7(), true, writer),
		"empty list":  runWriterHold(vectorDef(t, "vectorstore.records.delete"), writer, true),
		"unknown run": runWriterHold(vectorDef(t, "vectorstore.records.upsert"), writer, false, writer),
	} {
		if len(s.cl.items) != 1 || s.cl.items[0].Code != ReasonVectorWriteNotWriter || s.cl.items[0].effect != adomain.RequireApproval ||
			len(s.ev.Approvals) != 1 || len(s.ev.Requirements) != 1 {
			t.Errorf("%s: %+v %+v", name, s.cl.items, s.ev.Approvals)
		}
	}
}
