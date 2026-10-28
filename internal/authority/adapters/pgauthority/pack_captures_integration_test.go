// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package pgauthority_test

import (
	"context"
	"fmt"
	"slices"
	"testing"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	evapp "github.com/katocxl/pantherclaw/internal/evidence/app"
	"github.com/katocxl/pantherclaw/internal/evidence/capture"
	"github.com/katocxl/pantherclaw/internal/evidence/pack"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// halfCaptures opens a transaction's request and cannot open its response.
type halfCaptures struct{}

func (halfCaptures) Captures(_ context.Context, _ ids.OrgID, _, txn ids.UUID) ([]pack.File, error) {
	return []pack.File{{Path: "captures/" + txn.String() + "/request.bin", Kind: pack.KindCapture, Data: []byte(`{"amount":"10.00"}`)}},
		fmt.Errorf("%w: response", pack.ErrCaptureUnavailable)
}

// TestHR199_APackRecordsACaptureItCannotOpenAsAGap (G0 M7 deviation 4,
// #453 review): a payload capture that exists but cannot be opened is a
// not_captured gap of its transaction, never a failed pack, and the
// captures that could be opened are kept, both from the capture source
// over the audited read (here without the payload_captures envelope) and
// from a source that opens one capture of two.
func TestHR199_APackRecordsACaptureItCannotOpenAsAGap(t *testing.T) {
	w := newWorld(t)
	w.refundable("ch_1")
	txn := w.authorize(w.request(w.run(w.grant("500").ID, ids.UUID{}), ids.NewV7(), "ch_1", "10.00")).TransactionID
	p := w.packs(billing.Team)
	auditor := p.person("auditor", td.RoleAuditor, td.Scope{Type: td.ScopeOrg, ID: w.org.UUID()})
	req := evapp.PackRequest{Kind: pack.ScopeTransactions, Transactions: []ids.UUID{txn}, Include: pack.Include{Receipts: true, Captures: true}}
	gapOf := func(m *pack.Manifest) bool {
		return slices.ContainsFunc(m.Gaps, func(g pack.Gap) bool {
			return g.Reason == pack.GapNotCaptured && g.Subject == "captures of "+txn.String()
		})
	}

	p.builder.Captures = capture.PackSource{Service: &capture.Service{Pool: w.pool}}
	raw := p.download(auditor, p.create(auditor, req).ID)
	if m := manifestOf(t, raw); !gapOf(m) || len(m.Transactions) != 1 {
		t.Fatalf("a capture that cannot be opened: %d transactions, gaps %+v", len(m.Transactions), m.Gaps)
	}

	p.builder.Captures = halfCaptures{}
	raw = p.download(auditor, p.create(auditor, req).ID)
	files, err := pack.Read(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := files["captures/"+txn.String()+"/request.bin"]; !ok {
		t.Fatal("the capture that could be opened is not in the pack")
	}
	if _, ok := files["captures/"+txn.String()+"/response.bin"]; ok {
		t.Fatal("the capture that could not be opened is in the pack")
	}
	if m := manifestOf(t, raw); !gapOf(m) {
		t.Fatalf("one capture of two: gaps %+v", m.Gaps)
	}
}
