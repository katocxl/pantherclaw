// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package finalize_test

import (
	"context"
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// claimer is a fake CoverageClaimer that records the scope it was asked.
type claimer struct {
	claim *finalize.CoverageClaim
	err   error
	asked []string
}

func (c *claimer) CoverageClaim(_ context.Context, _ ids.OrgID, agent, connection ids.UUID, operation string, _ time.Time) (*finalize.CoverageClaim, error) {
	c.asked = append(c.asked, agent.String()+" "+connection.String()+" "+operation)
	return c.claim, c.err
}

func coverageOf(t *testing.T, receipt string) *finalize.CoverageClaim {
	t.Helper()
	var r finalize.DecisionReceipt
	if err := json.Unmarshal(pipelinetest.Payload(receipt), &r); err != nil {
		t.Fatal(err)
	}
	return r.Pap.Coverage
}

// TestHR217_ReceiptsCarryTheCoverageClaimOfTheirScope: a receipt of an
// action through a connection carries the claim of its agent, connection
// and operation; a failed claim read drops the claim, never the decision;
// a scope never assessed has none, and the field is left out entirely, so
// receipts look as they did before M9.
func TestHR217_ReceiptsCarryTheCoverageClaimOfTheirScope(t *testing.T) {
	s, run, conn := monitored(t)
	c := &claimer{claim: &finalize.CoverageClaim{State: "OBSERVE_ONLY", Snapshot: ids.NewV7().String(), Digest: "sha256:00"}}
	s.Authority.Coverage = c
	res := s.Authorize(throughConnection(t, s, run, conn, pipelinetest.Refund("ch_1", "30.00")))
	if got := coverageOf(t, res.Receipt); got == nil || *got != *c.claim {
		t.Fatalf("claim %+v, want %+v", got, c.claim)
	}
	if len(c.asked) != 1 || c.asked[0] != s.Agent.String()+" "+conn.String()+" payments.refund.create" {
		t.Fatalf("asked %v", c.asked)
	}
	c.claim, c.err = nil, errors.New("database unavailable")
	res = s.Authorize(throughConnection(t, s, run, conn, pipelinetest.Refund("ch_2", "30.00")))
	if res.Receipt == "" || coverageOf(t, res.Receipt) != nil {
		t.Fatalf("a failed claim read: receipt %q", res.Receipt)
	}
	c.err = nil
	res = s.Authorize(throughConnection(t, s, run, conn, pipelinetest.Refund("ch_3", "30.00")))
	if strings.Contains(string(pipelinetest.Payload(res.Receipt)), `"coverage"`) {
		t.Fatalf("a scope never assessed: receipt %s", pipelinetest.Payload(res.Receipt))
	}
}
