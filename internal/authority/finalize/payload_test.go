// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package finalize_test

import (
	"encoding/json/v2"
	"slices"
	"strings"
	"testing"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

var tokenFinding = []pipeline.PayloadFinding{{Kind: "github_token", Location: "arg:content(base64)"}}

func codes(r finalize.Result) []string {
	var out []string
	for _, x := range r.Reasons {
		out = append(out, x.Code)
	}
	return out
}

// TestHR225_ACredentialFormatHoldsForAPerson: an action the grant allows is
// held for a person's approval, reason SECRET_IN_PAYLOAD, when the gateway
// found a credential-shaped value in its payload; the decision receipt
// names the kind and place, and a receipt without findings has no such
// member.
func TestHR225_ACredentialFormatHoldsForAPerson(t *testing.T) {
	s, _, run := scenario(t)
	plain := s.Authorize(s.Request(run, ids.NewV7(), "create_refund", pipelinetest.Refund("ch_1", "30.00")))
	if plain.Decision != adomain.Allow || plain.Permit == "" {
		t.Fatalf("baseline: %s %v", plain.Decision, codes(plain))
	}
	if strings.Contains(string(pipelinetest.Payload(plain.Receipt)), "payload_findings") {
		t.Fatal("a receipt without findings carries the member")
	}

	s, _, run = scenario(t)
	req := s.Request(run, ids.NewV7(), "create_refund", pipelinetest.Refund("ch_1", "30.00"))
	req.PayloadFindings = tokenFinding
	held := s.Authorize(req)
	if held.Decision != adomain.RequireApproval || held.Permit != "" || held.Wait == nil || !slices.Contains(codes(held), pipeline.ReasonSecretInPayload) {
		t.Fatalf("held: %s %v permit %q wait %v", held.Decision, codes(held), held.Permit, held.Wait)
	}
	var receipt finalize.DecisionReceipt
	if err := json.Unmarshal(pipelinetest.Payload(held.Receipt), &receipt); err != nil {
		t.Fatal(err)
	}
	rc := receipt.Pap
	if !slices.Equal(rc.PayloadFindings, []finalize.ReceiptFinding{{Kind: "github_token", Location: "arg:content(base64)"}}) {
		t.Fatalf("receipt findings %+v", rc.PayloadFindings)
	}
	if len(rc.Approvals) == 0 {
		t.Fatal("the receipt names no approval requirement")
	}
}

// TestHR225_FindingsOnlyEverAddRequirements: whatever the baseline decision,
// findings never turn a refusal into a permit and never remove a reason:
// ALLOW becomes a hold, anything else stays what it was.
func TestHR225_FindingsOnlyEverAddRequirements(t *testing.T) {
	for name, tc := range map[string]struct{ charge, amount string }{
		"allowed":      {"ch_1", "30.00"},
		"over bounds":  {"ch_1", "5000.00"},
		"fact missing": {"ch_9", "10.00"},
	} {
		s, _, run := scenario(t)
		act := ids.NewV7()
		without := s.Authorize(s.Request(run, act, "create_refund", pipelinetest.Refund(tc.charge, tc.amount)))
		s2, _, run2 := scenario(t)
		req := s2.Request(run2, act, "create_refund", pipelinetest.Refund(tc.charge, tc.amount))
		req.PayloadFindings = tokenFinding
		with := s2.Authorize(req)
		switch {
		case without.Decision == adomain.Allow:
			if with.Decision != adomain.RequireApproval || with.Permit != "" {
				t.Errorf("%s: allow became %s", name, with.Decision)
			}
		case with.Decision != without.Decision || with.Permit != "":
			t.Errorf("%s: %s became %s", name, without.Decision, with.Decision)
		}
		for _, c := range codes(without) {
			// An allow's passing reasons give way to the hold's; a refusal's stay.
			if without.Decision != adomain.Allow && !slices.Contains(codes(with), c) {
				t.Errorf("%s: the reason %s was removed", name, c)
			}
		}
	}
}

// TestT093_ExfiltrationOverAnAllowedChannelIsHeld: a credential-shaped value
// sent through an operation and destination the grant allows is not
// dispatched on the grant alone, however the findings are repeated or
// reordered.
func TestT093_ExfiltrationOverAnAllowedChannelIsHeld(t *testing.T) {
	s, _, run := scenario(t)
	req := s.Request(run, ids.NewV7(), "create_refund", pipelinetest.Refund("ch_1", "1.00"))
	req.PayloadFindings = []pipeline.PayloadFinding{
		{Kind: "slack_token", Location: "arg:b"}, {Kind: "github_token", Location: "arg:a"}, {Kind: "slack_token", Location: "arg:b"},
	}
	r := s.Authorize(req)
	if r.Decision != adomain.RequireApproval || r.Permit != "" {
		t.Fatalf("%s %v", r.Decision, codes(r))
	}
	var receipt finalize.DecisionReceipt
	if err := json.Unmarshal(pipelinetest.Payload(r.Receipt), &receipt); err != nil {
		t.Fatal(err)
	}
	rc := receipt.Pap
	want := []finalize.ReceiptFinding{{Kind: "github_token", Location: "arg:a"}, {Kind: "slack_token", Location: "arg:b"}}
	if !slices.Equal(rc.PayloadFindings, want) {
		t.Fatalf("%+v", rc.PayloadFindings)
	}
}
