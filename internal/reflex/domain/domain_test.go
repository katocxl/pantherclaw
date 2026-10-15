// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

func signal() reflexdomain.Signal {
	return reflexdomain.Signal{
		Org: ids.New[ids.Org](), Source: reflexdomain.SourceDetection, RuleID: "pc.tools.drift", RuleVersion: "1",
		RuleDigest: strings.Repeat("a", 64), PackVersion: "1", Title: "Tool definition drifted",
		Severity: reflexdomain.SeverityHigh, Attention: reflexdomain.AttentionAlert, Basis: reflexdomain.BasisRuleMatch,
		Subjects:   []reflexdomain.Subject{{Type: reflexdomain.SubjectConnection, ID: "c1"}},
		Evidence:   []reflexdomain.EvidenceRef{{Kind: reflexdomain.EvidenceLedger, ID: ids.NewV7()}},
		OccurredAt: time.Now(), Facts: map[string]string{"package": "p"},
	}
}

func TestSignalValidate(t *testing.T) {
	if err := signal().Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*reflexdomain.Signal){
		"no org":    func(s *reflexdomain.Signal) { s.Org = ids.OrgID{} },
		"source":    func(s *reflexdomain.Signal) { s.Source = "elsewhere" },
		"no digest": func(s *reflexdomain.Signal) { s.RuleDigest = "" },
		"severity":  func(s *reflexdomain.Signal) { s.Severity = "URGENT" },
		"attention": func(s *reflexdomain.Signal) { s.Attention = "LOUD" },
		"basis":     func(s *reflexdomain.Signal) { s.Basis = "GUESS" },
		"subject":   func(s *reflexdomain.Signal) { s.Subjects = []reflexdomain.Subject{{Type: "planet", ID: "x"}} },
		"evidence": func(s *reflexdomain.Signal) {
			s.Evidence = []reflexdomain.EvidenceRef{{Kind: "rumour", ID: ids.NewV7()}}
		},
		"fact key":        func(s *reflexdomain.Signal) { s.Facts = map[string]string{"Bad Key": "x"} },
		"fact value":      func(s *reflexdomain.Signal) { s.Facts = map[string]string{"k": strings.Repeat("x", 513)} },
		"title":           func(s *reflexdomain.Signal) { s.Title = "" },
		"no time":         func(s *reflexdomain.Signal) { s.OccurredAt = time.Time{} },
		"too many facts":  func(s *reflexdomain.Signal) { s.Facts = manyFacts(17) },
		"too many atlas":  func(s *reflexdomain.Signal) { s.ATLAS = make([]string, 17) },
		"long dedupe key": func(s *reflexdomain.Signal) { s.DedupeKey = strings.Repeat("k", 513) },
	} {
		s := signal()
		mut(&s)
		if err := s.Validate(); !errors.Is(err, reflexdomain.ErrInvalidSignal) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func manyFacts(n int) map[string]string {
	m := map[string]string{}
	for i := range n {
		m["k"+strings.Repeat("x", i)] = "v"
	}
	return m
}

func TestAttentionOrder(t *testing.T) {
	order := []reflexdomain.Attention{
		reflexdomain.AttentionTelemetry, reflexdomain.AttentionLive, reflexdomain.AttentionFinding,
		reflexdomain.AttentionAlert, reflexdomain.AttentionIncident, reflexdomain.AttentionPage,
	}
	for i := 1; i < len(order); i++ {
		if !order[i].AtLeast(order[i-1]) || order[i-1].AtLeast(order[i]) {
			t.Errorf("%s vs %s", order[i-1], order[i])
		}
	}
	if reflexdomain.Attention("X").AtLeast(reflexdomain.AttentionTelemetry) {
		t.Error("unknown attention ranks")
	}
}

func TestReflexKind(t *testing.T) {
	if !reflexdomain.ReflexKind(reflexdomain.KindAlert) || reflexdomain.ReflexKind("receipt.decision") {
		t.Error("ReflexKind")
	}
}

func TestSystemSubjectsAreFixedNames(t *testing.T) {
	for _, id := range []string{reflexdomain.SystemIdentityPlaybook, reflexdomain.SystemDetection, reflexdomain.SystemSweeper} {
		if !(reflexdomain.Subject{Type: reflexdomain.SubjectSystem, ID: id}).Valid() {
			t.Errorf("%s invalid", id)
		}
	}
	if (reflexdomain.Subject{Type: reflexdomain.SubjectSystem, ID: "root"}).Valid() {
		t.Error("an unknown system actor is valid")
	}
}
