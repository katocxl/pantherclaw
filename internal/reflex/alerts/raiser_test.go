// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package alerts_test

import (
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/reflex/alerts"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	"github.com/katocxl/pantherclaw/internal/reflex/feed"
)

// TestHR665_AlertEntryKeepsTheEventKind: an alert's ledger entry carries its
// signal's event kind and no other fact, the feed reads it back as the
// event_kind attribute an alert trigger filters on, and the kind survives
// the cut of an entry over 8 KiB. A signal without one has none.
func TestHR665_AlertEntryKeepsTheEventKind(t *testing.T) {
	run := reflexdomain.Subject{Type: reflexdomain.SubjectRun, ID: ids.NewV7().String()}
	s := reflexdomain.Signal{
		Source: reflexdomain.SourceDetection, RuleID: "pc.authority.self_issue", Severity: reflexdomain.SeverityHigh,
		Attention: reflexdomain.AttentionAlert, Basis: reflexdomain.BasisObserved, Subjects: []reflexdomain.Subject{run},
		Facts: map[string]string{"event_kind": "audit.grant.delegate_refused", "operation": "grant.delegate", "count": "1"},
	}
	read := func(s reflexdomain.Signal) feed.Event {
		t.Helper()
		body := alerts.EntryBody(s, ids.NewV7(), alerts.StateOpen)
		if len(body) > reflexdomain.MaxLedgerBody {
			t.Fatalf("entry of %d bytes", len(body))
		}
		e, err := feed.Normalize(reflexdomain.KindAlert, alerts.Actor.Type, alerts.Actor.ID, time.Now(), body)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	e := read(s)
	if e.Attrs["event_kind"] != "audit.grant.delegate_refused" {
		t.Fatalf("attrs %v: no event kind", e.Attrs)
	}
	if _, ok := e.Attrs["operation"]; ok {
		t.Errorf("attrs %v: a fact other than the event kind reached the feed", e.Attrs)
	}
	if id, ok := e.Subject(reflexdomain.SubjectRun); !ok || id != run.ID {
		t.Errorf("subjects %v: the run is lost", e.Subjects)
	}

	big := s
	for i := range 64 {
		big.Subjects = append(big.Subjects, reflexdomain.Subject{Type: reflexdomain.SubjectResource, ID: strings.Repeat("r", 200) + string(rune('a'+i%26))})
	}
	if e := read(big); e.Attrs["event_kind"] != "audit.grant.delegate_refused" {
		t.Errorf("attrs %v: the cut lost the event kind", e.Attrs)
	}
	// One subject over the limit leaves only the minimal entry.
	huge := s
	huge.Subjects = []reflexdomain.Subject{{Type: reflexdomain.SubjectResource, ID: strings.Repeat("r", reflexdomain.MaxLedgerBody)}}
	if e := read(huge); e.Attrs["event_kind"] != "audit.grant.delegate_refused" || len(e.Subjects) != 0 {
		t.Errorf("attrs %v, subjects %v: the minimal entry lost the event kind", e.Attrs, e.Subjects)
	}

	none := s
	none.Facts = map[string]string{"count": "1"}
	if e := read(none); e.Attrs["event_kind"] != "" {
		t.Errorf("attrs %v: an event kind from nowhere", e.Attrs)
	}
}
