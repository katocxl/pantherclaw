// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"errors"
	"testing"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	tsapp "github.com/katocxl/pantherclaw/internal/ticketsync/app"
)

// TestF833_TicketRefsAndTheSyncLogRead: a case's links and a configuration's
// log read back, newest first and paged, with both directions; another
// configuration's log is not found, and below Business nothing reads.
//
// Covers: F833
func TestF833_TicketRefsAndTheSyncLogRead(t *testing.T) {
	f := newFixture(t)
	kase, _ := f.containedCase()
	refs, err := f.svc.RefsOfCase(f.as(), kase)
	if err != nil || len(refs) != 1 || refs[0].Key != "SEC-7" || refs[0].Case == nil || *refs[0].Case != kase {
		t.Fatalf("links: %+v, %v", refs, err)
	}
	if refs, err := f.svc.RefsOfIncident(f.as(), ids.NewV7()); err != nil || len(refs) != 0 {
		t.Fatalf("an incident with no ticket: %+v, %v", refs, err)
	}

	other := f.openCase("another")
	outbound, err := f.svc.OpenCaseTicket(f.as(), other, f.config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.deliver("d-1", statusEvent(1_900_000_000, "Done", "done"), f.secret); err != nil {
		t.Fatal(err)
	}

	first, next, err := f.svc.SyncEvents(f.as(), f.config, page.Request{Size: 1})
	if err != nil || len(first) != 1 || next == "" {
		t.Fatalf("first page: %+v, %q, %v", first, next, err)
	}
	if e := first[0]; e.Direction != "INBOUND" || e.Status == "" || e.IssueKey != "SEC-7" || e.CaseID != "" {
		t.Fatalf("the inbound event: %+v", e)
	}
	pr, err := page.Parse(1, next)
	if err != nil {
		t.Fatal(err)
	}
	second, next, err := f.svc.SyncEvents(f.as(), f.config, pr)
	if err != nil || len(second) != 1 || next != "" {
		t.Fatalf("second page: %+v, %q, %v", second, next, err)
	}
	if e := second[0]; e.Direction != "OUTBOUND" || e.ID != outbound || e.Action != "CREATE" || e.Status != "PENDING" || e.CaseID != other.String() || e.IssueKey != "" {
		t.Fatalf("the outbound event: %+v", e)
	}

	if _, _, err := f.svc.SyncEvents(f.as(), ids.NewV7(), page.Request{Size: 1}); !errors.Is(err, tsapp.ErrNotFound) {
		t.Fatalf("an unknown configuration: %v", err)
	}
	f.svc.Editions = edition(billing.Team)
	if _, _, err := f.svc.SyncEvents(f.as(), f.config, page.Request{Size: 1}); !errors.Is(err, tsapp.ErrEdition) {
		t.Fatalf("the log below Business: %v", err)
	}
	if _, err := f.svc.RefsOfCase(f.as(), kase); !errors.Is(err, tsapp.ErrEdition) {
		t.Fatalf("links below Business: %v", err)
	}
}
