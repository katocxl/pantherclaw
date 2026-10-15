// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package ocsf

import (
	"bytes"
	"encoding/json/v2"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

var at = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

func event(kind string) Event {
	return Event{
		Seq: 42, ID: mustUUID("0192f0a0-0000-7000-8000-000000000001"), Org: ids.MustParse[ids.Org]("0192f0a0-0000-7000-8000-0000000000aa"), Kind: kind,
		OccurredAt: at, ActorType: "agent", ActorID: "0192f0a0-0000-7000-8000-0000000000bb",
		Subjects: []reflexdomain.Subject{{Type: reflexdomain.SubjectRun, ID: "r1"}},
	}
}

func TestMapClasses(t *testing.T) {
	cases := []struct {
		name                string
		ev                  func() Event
		class, category, ty int
		severity, status    int
		check               func(t *testing.T, r Record)
	}{
		{
			name: "decision deny", class: 6003, category: 6, ty: 600302, severity: 2, status: 2,
			ev: func() Event {
				e := event("receipt.decision")
				e.Decision, e.Reason, e.Operation, e.Mode = "DENY", "NO_GRANT", "github.repo.read", "ENFORCED"
				e.Attrs = map[string]string{AttrPolicyVersion: "pv-7", AttrEffect: "none", AttrCoverage: "ENFORCED", "transaction": "t1"}
				return e
			},
			check: func(t *testing.T, r Record) {
				if len(r.Authorizations) != 1 || r.Authorizations[0].Decision != "DENY" || r.Authorizations[0].Policy.Version != "pv-7" ||
					r.Authorizations[0].Policy.Desc != "NO_GRANT" {
					t.Errorf("authorizations = %+v", r.Authorizations)
				}
				if r.API == nil || r.API.Operation != "github.repo.read" || r.SrcEndpoint == nil {
					t.Errorf("api = %+v, src = %+v", r.API, r.SrcEndpoint)
				}
				if r.Unmapped.Effect != "none" || r.Unmapped.Coverage != "ENFORCED" || r.Unmapped.Attrs["transaction"] != "t1" ||
					r.Unmapped.Uncertainty != "" {
					t.Errorf("unmapped = %+v", r.Unmapped)
				}
				if _, leaked := r.Unmapped.Attrs[AttrPolicyVersion]; leaked {
					t.Error("a mapped attribute is repeated in unmapped")
				}
			},
		},
		{
			name: "decision allow observe-only", class: 6003, category: 6, ty: 600303, severity: 1, status: 1,
			ev: func() Event {
				e := event("receipt.decision")
				e.Decision, e.Operation, e.Mode = "ALLOW", "files.update", "OBSERVE_ONLY"
				return e
			},
			check: func(t *testing.T, r Record) {
				if r.Unmapped.Uncertainty != "mode:OBSERVE_ONLY" {
					t.Errorf("uncertainty = %q", r.Unmapped.Uncertainty)
				}
			},
		},
		{
			name: "held decision", class: 6003, category: 6, ty: 600399, severity: 1, status: 99,
			ev: func() Event {
				e := event("receipt.decision")
				e.Decision, e.Operation = "HOLD", "payments.transfer"
				return e
			},
		},
		{
			name: "alert", class: 2004, category: 2, ty: 200401, severity: 4, status: 1,
			ev: func() Event {
				e := event("reflex.alert")
				e.Attrs = map[string]string{
					AttrRuleID: "pc.authority.self_issue", AttrRuleVersion: "1", AttrTitle: "Self-issued grant", AttrSeverity: "HIGH",
					AttrState: "OPEN", AttrID: "alert-1", AttrBasis: "RULE_MATCH", AttrATLAS: "AML.T0051, AML.T0053", AttrOWASP: "ASI03",
				}
				return e
			},
			check: func(t *testing.T, r Record) {
				f := r.FindingInfo
				if f == nil || f.UID != "alert-1" || f.Analytic.UID != "pc.authority.self_issue" || len(f.Attacks) != 2 ||
					f.Attacks[1].Technique.UID != "AML.T0053" || len(f.Types) != 1 || f.Types[0] != "ASI03" {
					t.Errorf("finding = %+v", f)
				}
				if r.Unmapped.Uncertainty != "RULE_MATCH" {
					t.Errorf("uncertainty = %q", r.Unmapped.Uncertainty)
				}
			},
		},
		{
			name: "suppressed alert", class: 2004, category: 2, ty: 200402, severity: 2, status: 3,
			ev: func() Event {
				e := event("reflex.alert")
				e.Attrs = map[string]string{AttrSeverity: "LOW", AttrState: "SUPPRESSED"}
				return e
			},
		},
		{
			name: "incident", class: 2005, category: 2, ty: 200503, severity: 5, status: 5,
			ev: func() Event {
				e := event("reflex.incident")
				e.Attrs = map[string]string{AttrSeverity: "CRITICAL", AttrState: "CLOSED", AttrTitle: "Run contained"}
				return e
			},
			check: func(t *testing.T, r Record) {
				if len(r.FindingList) != 1 || r.FindingList[0].Title != "Run contained" {
					t.Errorf("finding list = %+v", r.FindingList)
				}
			},
		},
		{
			name: "account change", class: 3001, category: 3, ty: 300105, severity: 1, status: 1,
			ev: func() Event {
				e := event("audit.user.disabled")
				e.ActorType, e.Outcome = "user", "SUCCESS"
				e.Subjects = []reflexdomain.Subject{{Type: reflexdomain.SubjectUser, ID: "u9"}}
				return e
			},
			check: func(t *testing.T, r Record) {
				if r.User == nil || r.User.UID != "u9" || r.User.TypeID != 1 || r.Actor.User.Type != "User" {
					t.Errorf("user = %+v actor = %+v", r.User, r.Actor)
				}
			},
		},
		{
			name: "other audit", class: 6003, category: 6, ty: 600301, severity: 1, status: 0,
			ev: func() Event { return event("audit.siem.destination_created") },
		},
		{
			name: "coverage", class: 0, category: 0, ty: 99, severity: 1, status: 0,
			ev: func() Event { return event("coverage.invalidation") },
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := c.ev()
			r := Map(e, "0.1.0")
			if r.ClassUID != c.class || r.CategoryUID != c.category || r.TypeUID != c.ty || r.SeverityID != c.severity || r.StatusID != c.status {
				t.Errorf("class %d category %d type %d severity %d status %d, want %d %d %d %d %d",
					r.ClassUID, r.CategoryUID, r.TypeUID, r.SeverityID, r.StatusID, c.class, c.category, c.ty, c.severity, c.status)
			}
			if r.Metadata.UID != e.ID.String() || r.Metadata.Sequence != 42 || r.Metadata.Version != "1.9.0" || r.Metadata.EventCode != e.Kind ||
				r.Metadata.TenantUID != e.Org.String() || r.Time != at.UnixMilli() || r.Metadata.Product.Version != "0.1.0" {
				t.Errorf("metadata = %+v time %d", r.Metadata, r.Time)
			}
			if len(r.Resources) != len(e.Subjects) {
				t.Errorf("resources = %+v", r.Resources)
			}
			if c.check != nil {
				c.check(t, r)
			}
		})
	}
}

func TestMapIsDeterministic(t *testing.T) {
	e := event("receipt.decision")
	e.Decision = "ALLOW"
	e.Attrs = map[string]string{"a": "1", "b": "2", "c": "3", "d": "4", "e": "5", "f": "6"}
	first, err := Encode(Map(e, ""))
	if err != nil {
		t.Fatal(err)
	}
	for range 20 {
		again, err := Encode(Map(e, ""))
		if err != nil || !bytes.Equal(first, again) {
			t.Fatalf("encoding changed: %s vs %s (%v)", first, again, err)
		}
	}
}

func TestTestEventsAreLabelled(t *testing.T) {
	e := event("reflex.alert")
	e.Test = true
	if r := Map(e, ""); len(r.Metadata.Labels) != 1 || r.Metadata.Labels[0] != "test" {
		t.Errorf("labels = %v", r.Metadata.Labels)
	}
}

func TestClassOf(t *testing.T) {
	cases := map[string]DataClass{
		"receipt.decision": ClassDecisions, "receipt.effect": ClassDecisions, "reflex.alert": ClassAlerts,
		"reflex.incident": ClassIncidents, "reflex.case": ClassIncidents, "response.action": ClassContainment,
		"audit.containment.kill_switch_engaged": ClassContainment, "coverage.snapshot": ClassCoverage,
		"sandbox.closure": ClassCoverage, "posture.finding": ClassCoverage, "audit.grant.revoked": ClassAudit,
	}
	for kind, want := range cases {
		if got, ok := ClassOf(kind); !ok || got != want {
			t.Errorf("ClassOf(%q) = %q %v, want %q", kind, got, ok, want)
		}
	}
	// Unknown and live kinds are never exported (F3: nothing unmapped leaves).
	for _, kind := range []string{"reflex.live", "unknown.kind", "", "receiptx"} {
		if c, ok := ClassOf(kind); ok {
			t.Errorf("ClassOf(%q) = %q, want none", kind, c)
		}
	}
	e := event("audit.grant.revoked")
	if Selected(e, []DataClass{ClassDecisions, ClassAlerts}) || !Selected(e, []DataClass{ClassAudit}) {
		t.Error("Selected ignores the destination's data classes")
	}
}

func TestBuilderBounds(t *testing.T) {
	var b Builder
	small := []byte(`{"x":1}`)
	for i := range MaxBatchEvents {
		if ok, err := b.Add(small); !ok || err != nil {
			t.Fatalf("add %d: %v %v", i, ok, err)
		}
	}
	if ok, _ := b.Add(small); ok {
		t.Fatal("a batch took more than 100 events")
	}
	body, err := b.Body("b1", 10, 20)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Type string `json:"type"`
		Data struct {
			Batch   string           `json:"batch"`
			FromSeq int64            `json:"from_seq"`
			ToSeq   int64            `json:"to_seq"`
			Events  []map[string]int `json:"events"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &got); err != nil || got.Type != BatchType || got.Data.Batch != "b1" || got.Data.FromSeq != 10 ||
		got.Data.ToSeq != 20 || len(got.Data.Events) != 100 {
		t.Fatalf("body = %s (%v)", body, err)
	}

	var big Builder
	half := []byte(`"` + strings.Repeat("a", MaxBatchBytes/2) + `"`)
	if ok, err := big.Add(half); !ok || err != nil {
		t.Fatalf("first half: %v %v", ok, err)
	}
	if ok, err := big.Add(half); ok || err != nil {
		t.Fatalf("a batch went past 1 MiB: %v %v", ok, err)
	}
	if _, err := big.Add(make([]byte, MaxBatchBytes)); err != ErrEventTooLarge {
		t.Fatalf("oversize event: %v", err)
	}
}

func mustUUID(s string) ids.UUID {
	u, err := ids.ParseUUID(s)
	if err != nil {
		panic(err)
	}
	return u
}
