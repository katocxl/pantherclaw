// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline

import (
	"context"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// classReader serves one pc.classification fact about crm.contact c_1.
type classReader struct {
	Reader
	fact *fdomain.Fact
}

func (r classReader) Facts(_ context.Context, _ ids.OrgID, _ ids.UUID, subjectType, subjectID string, names []string) (map[string]fdomain.Fact, error) {
	out := map[string]fdomain.Fact{}
	if r.fact != nil && subjectType == "crm.contact" && subjectID == "c_1" && len(names) == 1 && names[0] == fdomain.NameClassification {
		out[fdomain.NameClassification] = *r.fact
	}
	return out, nil
}

func classified(class string, age time.Duration, now time.Time) *fdomain.Fact {
	return &fdomain.Fact{
		Name: fdomain.NameClassification, SubjectType: "crm.contact", SubjectID: "c_1", ObservedAt: now.Add(-age),
		Value: fdomain.Value{Type: fdomain.TypeIdentifier, Str: class}, Source: "catalog", Method: "rule", Kind: fdomain.KindClassification,
	}
}

func readState(now time.Time, response string) *state {
	d := &defs.Definition{Operation: "crm.contact.read", Access: defs.AccessRead}
	if response != "" {
		d.Response = &defs.ResponseSpec{Format: "json", Fields: []defs.ResponseField{{Path: "email", Class: response}}}
	}
	return &state{
		req: Request{Org: ids.New[ids.Org]()}, ev: &Evaluation{}, cont: Containment{Now: now}, def: d,
		a: actionir.ActionIR{Operation: "crm.contact.read", Target: actionir.Target{Type: "crm.contact", ID: "c_1"}},
	}
}

// TestHR435_AClassificationOnlyRaises: a fresh pc.classification fact
// raises a read's class; one below the declared class never lowers it; a
// stale one is ignored with a note; none has no effect.
// Covers: F366
func TestHR435_AClassificationOnlyRaises(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	run := func(response string, f *fdomain.Fact) *state {
		s := readState(now, response)
		if !(&Pipeline{Reader: classReader{fact: f}}).classify(context.Background(), s) {
			t.Fatal("the read failed")
		}
		s.readClass()
		return s
	}
	if s := run("internal", classified("secret", time.Hour, now)); s.ev.ReadClass != "secret" {
		t.Errorf("raised: %q, want secret", s.ev.ReadClass)
	}
	if s := run("pii", classified("public", time.Hour, now)); s.ev.ReadClass != "pii" {
		t.Errorf("lowered: %q, want pii", s.ev.ReadClass)
	}
	s := run("internal", classified("secret", ClassificationMaxAge+time.Minute, now))
	if s.ev.ReadClass != "internal" || len(s.cl.items) != 1 || s.cl.items[0].Code != ReasonClassificationStale {
		t.Errorf("stale: %q %+v", s.ev.ReadClass, s.cl.items)
	}
	if s := run("", nil); s.ev.ReadClass != "" || len(s.cl.items) != 0 {
		t.Errorf("none: %q %+v", s.ev.ReadClass, s.cl.items)
	}
	w := readState(now, "")
	w.def.Access = defs.AccessWrite
	if !(&Pipeline{Reader: classReader{fact: classified("secret", time.Hour, now)}}).classify(context.Background(), w) || w.classification != "" {
		t.Error("a write read a classification")
	}
}

// TestT191_APublicClassificationCannotHideASensitiveRead: marking a pii
// target public leaves the read pii, so the data-flow hold still sees it.
// Covers: F366
func TestT191_APublicClassificationCannotHideASensitiveRead(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := readState(now, "pii")
	(&Pipeline{Reader: classReader{fact: classified("public", time.Minute, now)}}).classify(context.Background(), s)
	s.readClass()
	if s.ev.ReadClass != "pii" {
		t.Fatalf("read class %q, want pii", s.ev.ReadClass)
	}
}

// TestHR435_OnlyAClassificationWithProvenanceRaises: a pc.classification
// fact of a value-kind declaration (from before M16), or one without its
// provenance, is ignored with a note.
// Covers: F366
func TestHR435_OnlyAClassificationWithProvenanceRaises(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	value := classified("secret", time.Minute, now)
	value.Kind = fdomain.KindValue
	bare := classified("secret", time.Minute, now)
	bare.Source, bare.Method = "", ""
	for name, f := range map[string]*fdomain.Fact{"value kind": value, "no provenance": bare} {
		s := readState(now, "internal")
		(&Pipeline{Reader: classReader{fact: f}}).classify(context.Background(), s)
		s.readClass()
		if s.ev.ReadClass != "internal" || len(s.cl.items) != 1 || s.cl.items[0].Code != ReasonClassificationIgnored {
			t.Errorf("%s: %q %+v", name, s.ev.ReadClass, s.cl.items)
		}
	}
}
