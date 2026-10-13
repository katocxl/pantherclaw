// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package finalize_test

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"reflect"
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
	delay time.Duration
	asked []string
}

func (c *claimer) CoverageClaim(ctx context.Context, _ ids.OrgID, agent, connection ids.UUID, operation string, _ time.Time) (*finalize.CoverageClaim, error) {
	c.asked = append(c.asked, agent.String()+" "+connection.String()+" "+operation)
	select {
	case <-time.After(c.delay):
		return c.claim, c.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
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
// and operation; a failed or slow claim read never fails the decision and
// says the claim is unavailable, and why, with nothing else; a claim read
// is bounded by the authority's claim timeout;
// a scope never assessed has none, and the field is left out entirely, so
// receipts look as they did before M9.
func TestHR217_ReceiptsCarryTheCoverageClaimOfTheirScope(t *testing.T) {
	s, run, conn := monitored(t)
	c := &claimer{claim: &finalize.CoverageClaim{
		V: 1, State: "PARTIAL", Snapshot: ids.NewV7().String(), SnapshotState: "ENFORCED", Lapsed: true, Reason: "expired",
		Exclusions: []string{ids.NewV7().String()},
	}}
	s.Authority.Coverage = c
	res := s.Authorize(throughConnection(t, s, run, conn, pipelinetest.Refund("ch_1", "30.00")))
	if got := coverageOf(t, res.Receipt); got == nil || !reflect.DeepEqual(*got, *c.claim) {
		t.Fatalf("claim %+v, want %+v", got, c.claim)
	}
	if len(c.asked) != 1 || c.asked[0] != s.Agent.String()+" "+conn.String()+" payments.refund.create" {
		t.Fatalf("asked %v", c.asked)
	}
	c.claim, c.err = nil, errors.New("database unavailable")
	res = s.Authorize(throughConnection(t, s, run, conn, pipelinetest.Refund("ch_2", "30.00")))
	if got := unavailableOf(t, res.Receipt); got != `{"unavailable":"error"}` {
		t.Fatalf("a failed claim read: coverage %s", got)
	}
	c.claim, c.err, c.delay = &finalize.CoverageClaim{V: 1, State: "PARTIAL"}, nil, time.Second
	res = s.Authorize(throughConnection(t, s, run, conn, pipelinetest.Refund("ch_4", "30.00")))
	if got := unavailableOf(t, res.Receipt); got != `{"unavailable":"timeout"}` {
		t.Fatalf("a slow claim read: coverage %s", got)
	}
	// The timeout is the authority's: a read within it carries the claim.
	s.Authority.ClaimTimeout, c.delay = 2*time.Second, 100*time.Millisecond
	res = s.Authorize(throughConnection(t, s, run, conn, pipelinetest.Refund("ch_5", "30.00")))
	if got := coverageOf(t, res.Receipt); got == nil || got.State != "PARTIAL" || got.Unavailable != "" {
		t.Fatalf("a read within the claim timeout: %+v", got)
	}
	c.claim, c.delay = nil, 0
	res = s.Authorize(throughConnection(t, s, run, conn, pipelinetest.Refund("ch_3", "30.00")))
	if strings.Contains(string(pipelinetest.Payload(res.Receipt)), `"coverage"`) {
		t.Fatalf("a scope never assessed: receipt %s", pipelinetest.Payload(res.Receipt))
	}
}

// unavailableOf returns the receipt's coverage claim as it was signed.
func unavailableOf(t *testing.T, receipt string) string {
	t.Helper()
	var r struct {
		Pap struct {
			Coverage jsontext.Value `json:"coverage"`
		} `json:"pap"`
	}
	if err := json.Unmarshal(pipelinetest.Payload(receipt), &r); err != nil {
		t.Fatal(err)
	}
	return string(r.Pap.Coverage)
}
