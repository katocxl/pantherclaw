// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package finalize_test

import (
	"testing"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline/pipelinetest"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestAuthorizeKeepsInputsWithEveryReceipt: each evaluation that writes a
// receipt writes its sealed inputs with it, the tampering denial too (with
// the request and the stored hash, nothing read); a repeat writes neither
// (G0 M7 design decision 11).
func TestAuthorizeKeepsInputsWithEveryReceipt(t *testing.T) {
	s, _, run := scenario(t)
	sealer := s.KeepInputs()
	act := ids.NewV7()
	open := s.Authorize(s.Request(run, act, "create_refund", pipelinetest.Refund("ch_9", "10.00")))
	if open.Decision != adomain.CannotAuthorize || decisive(open) != fdomain.ReasonFactMissing {
		t.Fatalf("open: %+v", open)
	}
	tampered := s.Authorize(s.Request(run, act, "create_refund", pipelinetest.Refund("ch_9", "11.00")))
	if decisive(tampered) != adomain.ReasonActionTampered || tampered.Evaluation != 2 {
		t.Fatalf("tampered: %+v", tampered)
	}
	first, second := s.W.Inputs(open.TransactionID, 1), s.W.Inputs(open.TransactionID, 2)
	if first == nil || second == nil {
		t.Fatalf("inputs = %v, %v", first, second)
	}
	r1, err := sealer.Open(t.Context(), s.Org, open.TransactionID, 1, *first)
	if err != nil {
		t.Fatal(err)
	}
	if r1.Tampered != nil || r1.Reads.Containment == nil || len(r1.Reads.Facts) != 1 {
		t.Fatalf("evaluation 1 = %+v", r1)
	}
	r2, err := sealer.Open(t.Context(), s.Org, open.TransactionID, 2, *second)
	if err != nil {
		t.Fatal(err)
	}
	if r2.Tampered == nil || r2.Tampered.StoredActionHash != open.ActionHash || r2.Reads.Containment != nil {
		t.Fatalf("evaluation 2 = %+v", r2)
	}

	ok := s.Authorize(s.Request(run, ids.NewV7(), "create_refund", pipelinetest.Refund("ch_1", "30.00")))
	if ok.Decision != adomain.Allow || s.W.Inputs(ok.TransactionID, 1) == nil {
		t.Fatalf("allow: %+v", ok)
	}
	if again := s.Authorize(s.Request(run, act, "create_refund", pipelinetest.Refund("ch_9", "10.00"))); !again.Repeat ||
		s.W.Inputs(open.TransactionID, 3) != nil {
		t.Fatalf("a repeat: %+v", again)
	}
}

// TestAuthorizeWithoutASealerKeepsNoInputs: an Authority configured
// without one records nothing (tests and tools only; the server always
// configures it).
func TestAuthorizeWithoutASealerKeepsNoInputs(t *testing.T) {
	s, _, run := scenario(t)
	ok := s.Authorize(s.Request(run, ids.NewV7(), "create_refund", pipelinetest.Refund("ch_1", "30.00")))
	if ok.Decision != adomain.Allow || s.W.Inputs(ok.TransactionID, 1) != nil {
		t.Fatalf("allow: %+v", ok)
	}
}
