// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline_test

import (
	"context"
	"testing"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// factSpy records the connection each fact read is made for.
type factSpy struct {
	pipeline.Reader
	conns *[]ids.UUID
}

func (s factSpy) Facts(ctx context.Context, org ids.OrgID, connection ids.UUID, subjectType, subjectID string, names []string) (map[string]fdomain.Fact, error) {
	*s.conns = append(*s.conns, connection)
	return s.Reader.Facts(ctx, org, connection, subjectType, subjectID, names)
}

// TestHR222_FactReadsAreMadeForTheActionsOwnConnection (D43): the pipeline
// asks for an action's facts through the connection the action names, never
// another one, and for an action through none with the zero id.
func TestHR222_FactReadsAreMadeForTheActionsOwnConnection(t *testing.T) {
	f := newFx(t)
	var conns []ids.UUID
	f.p = &pipeline.Pipeline{Reader: factSpy{Reader: f.w, conns: &conns}}
	for _, sim := range []bool{false, true} {
		conns = nil
		f.conn = f.simulatedConn(sim)
		ev := f.call(f.simulatedRun(sim), "create_refund", refund("ch_1", "10.00"))
		expect(t, ev, adomain.Allow, pipeline.ReasonGrantCovers)
		if len(conns) == 0 {
			t.Fatal("the pipeline read no facts")
		}
		for _, c := range conns {
			if c != f.conn {
				t.Errorf("simulated=%v: facts read for connection %s, want the action's %s", sim, c, f.conn)
			}
		}
	}
}
