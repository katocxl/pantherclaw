// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package restore

import (
	"context"
	"encoding/json/v2"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/securityevent"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

func sample() Event {
	return Event{Timestamp: time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC), Org: ids.New[ids.Org](), LedgerSeq: 3, Kind: "access.api_key_revoked", Direction: "tighten", Object: securityevent.Object{Type: "api_key", ID: ids.NewV7().String()}, Actor: domain.Actor{Type: "user", ID: ids.NewV7().String()}}
}
func line(t *testing.T, e Event) string {
	t.Helper()
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return string(b) + "\n"
}

// TestHR384_EntireInputValidatedBeforeReplay includes unknown events even
// before --since, direction tampering, missing D41 handlers and conflicts.
func TestHR384_EntireInputValidatedBeforeReplay(t *testing.T) {
	r := NewRegistry()
	base := sample()
	for _, change := range []func(*Event){func(e *Event) { e.Kind = "unknown.revoked" }, func(e *Event) { e.Direction = "loosen" }, func(e *Event) { e.Object.Type = "user" }, func(e *Event) { e.Object.ID = "not-an-id" }, func(e *Event) { e.LedgerSeq = 0 }, func(e *Event) { e.Timestamp = time.Time{} }, func(e *Event) {
		e.Kind = "org.deleted"
		e.Org = ids.PlatformOrg
		e.Object.Type = "org"
		e.RecordDigest = strings.Repeat("a", 64)
	}} {
		e := base
		change(&e)
		if _, err := r.Parse(strings.NewReader(line(t, e)), base.Timestamp.Add(time.Hour)); err == nil {
			t.Fatalf("accepted malformed event %+v", e)
		}
	}
	conflict := base
	conflict.Object.ID = ids.NewV7().String()
	if _, err := r.Parse(strings.NewReader(line(t, base)+line(t, conflict)), time.Time{}); err == nil {
		t.Fatal("accepted conflicting ledger sequence")
	}
}

func TestHR384_DeduplicatesAndSkipsOnlyKnownLoosening(t *testing.T) {
	r := NewRegistry()
	e := sample()
	loosen := e
	loosen.Kind = "access.user_enabled"
	loosen.Direction = "loosen"
	loosen.Object.Type = "user"
	loosen.LedgerSeq++
	got, err := r.Parse(strings.NewReader(line(t, e)+line(t, e)+line(t, loosen)), time.Time{})
	if err != nil || len(got) != 1 || got[0].Kind != e.Kind {
		t.Fatalf("parse = %+v %v", got, err)
	}
	if err := r.Reapply(context.Background(), nil, got, false, domain.Actor{Type: "operator", ID: "test"}); err == nil {
		t.Fatal("replay without hold succeeded")
	}
}

func TestHR384_ScopedRegistryIsClosed(t *testing.T) {
	r := NewRegistry()
	h := func(context.Context, *db.Pool, Event, domain.Actor) error { return nil }
	if err := r.RegisterScoped("access.api_key_revoked", h); err == nil {
		t.Fatal("ordinary kind escaped tenant scope")
	}
	if err := r.RegisterScoped("org.deleted", h); err != nil {
		t.Fatal(err)
	}
	if err := r.RegisterScoped("org.deleted", h); err == nil {
		t.Fatal("duplicate registration accepted")
	}
	for _, kind := range []string{"org.deletion_started", "account.deletion_started", "account.deleted"} {
		if err := r.RegisterScoped(kind, h); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHR384_ContainmentMetadataIsRequiredAndCanonical(t *testing.T) {
	e := sample()
	e.Kind = "response.contain"
	e.Object.Type = "containment_control"
	e.Containment = &securityevent.Containment{ActionID: ids.NewV7(), ControlID: mustID(t, e.Object.ID), ScopeType: "agent", ScopeID: ids.NewV7().String(), Control: "DENY_ALL", Source: "PERSON"}
	r := NewRegistry()
	if _, err := r.Parse(strings.NewReader(line(t, e)), time.Time{}); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Event){func(e *Event) { e.Containment = nil }, func(e *Event) { e.Containment.ScopeType = "org" }, func(e *Event) { e.Containment.Source = "operator" }, func(e *Event) { e.Containment.Control = "ALLOW" }, func(e *Event) { e.Containment.Operation = "unwanted" }, func(e *Event) { e.Containment.ScopeID = strings.Repeat("x", 301) }} {
		copyEvent := e
		copyMetadata := *e.Containment
		copyEvent.Containment = &copyMetadata
		change(&copyEvent)
		if _, err := r.Parse(strings.NewReader(line(t, copyEvent)), time.Time{}); err == nil {
			t.Fatalf("accepted invalid containment %+v", copyEvent)
		}
	}
}

func mustID(t *testing.T, s string) ids.UUID {
	t.Helper()
	id, err := ids.ParseUUID(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
