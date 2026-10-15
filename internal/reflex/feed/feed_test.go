// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package feed_test

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	"github.com/katocxl/pantherclaw/internal/reflex/feed"
)

const (
	txn   = "01930000-0000-7000-8000-000000000001"
	agent = "01930000-0000-7000-8000-0000000000a1"
	conn  = "01930000-0000-7000-8000-0000000000c1"
	grant = "01930000-0000-7000-8000-0000000000g1"
)

var at = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

func subject(t reflexdomain.SubjectType, id string) reflexdomain.Subject {
	return reflexdomain.Subject{Type: t, ID: id}
}

func TestNormalizeKinds(t *testing.T) {
	for _, tc := range []struct {
		kind, body string
		check      func(t *testing.T, e feed.Event)
	}{
		{
			"receipt.decision", `{"act":"x","decision":"DENY","evaluation":"1","monitor":"true","reason":"NO_GRANT","receipt_sha256":"ab","txn":"` + txn + `"}`,
			func(t *testing.T, e feed.Event) {
				if e.Decision != "DENY" || e.Reason != "NO_GRANT" || e.Mode != "MONITOR" || e.Attrs["evaluation"] != "1" {
					t.Errorf("%+v", e)
				}
				if !slices.Contains(e.Subjects, subject(reflexdomain.SubjectTransaction, txn)) {
					t.Errorf("subjects %v", e.Subjects)
				}
			},
		},
		{
			"receipt.execution", `{"outcome":"accepted","permit":"p1","receipt_sha256":"ab","txn":"` + txn + `"}`,
			func(t *testing.T, e feed.Event) {
				if e.Outcome != "accepted" || e.Attrs["permit"] != "p1" {
					t.Errorf("%+v", e)
				}
			},
		},
		{
			"receipt.effect", `{"receipt_sha256":"ab","seq":"2","state":"CONFIRMED","txn":"` + txn + `"}`,
			func(t *testing.T, e feed.Event) {
				if e.Outcome != "CONFIRMED" || e.Attrs["effect_seq"] != "2" {
					t.Errorf("%+v", e)
				}
			},
		},
		{
			"coverage.snapshot", `{"scope":{"agent":"` + agent + `","connection":"` + conn + `","operation":"github.push"},"state":"PARTIAL","snapshot":"s1"}`,
			func(t *testing.T, e feed.Event) {
				if e.Operation != "github.push" || e.Attrs["state"] != "PARTIAL" || len(e.Subjects) != 2 {
					t.Errorf("%+v", e)
				}
			},
		},
		{
			"coverage.invalidation", `{"agent":"` + agent + `","connection":"` + conn + `","id":"i1","kind":"credential_changed","occurred_at":"x","v":1}`,
			func(t *testing.T, e feed.Event) {
				if e.Reason != "credential_changed" || len(e.Subjects) != 2 {
					t.Errorf("%+v", e)
				}
			},
		},
		{
			"sandbox.closure", `{"agent":"` + agent + `","closure":"c","connections":["` + conn + `"],"result":"CLOSED"}`,
			func(t *testing.T, e feed.Event) {
				if e.Outcome != "CLOSED" || len(e.Subjects) != 2 {
					t.Errorf("%+v", e)
				}
			},
		},
		{
			"audit.grant.issued", `{"details":{"agent":"` + agent + `","expires_at":"2026","principal":"user:u1","client_secret":"no"},"name":"grant.issued","object":{"id":"` + grant + `","type":"grant"},"outcome":"success"}`,
			func(t *testing.T, e feed.Event) {
				if e.Outcome != "success" || e.Attrs["principal"] != "user:u1" || e.Attrs["object_type"] != "grant" {
					t.Errorf("%+v", e)
				}
				if _, ok := e.Attrs["client_secret"]; ok {
					t.Error("a secret-like attribute survived")
				}
				if !slices.Contains(e.Subjects, subject(reflexdomain.SubjectAgent, agent)) ||
					!slices.Contains(e.Subjects, subject(reflexdomain.SubjectGrant, grant)) {
					t.Errorf("subjects %v", e.Subjects)
				}
			},
		},
		{
			"audit.security.variant_suspected", `{"details":{"operation":"payments.refund","agent":"` + agent + `","count":"3"},"name":"security.variant_suspected","outcome":"denied","reason_code":"VARIANT_SHOPPING"}`,
			func(t *testing.T, e feed.Event) {
				if e.Operation != "payments.refund" || e.Reason != "VARIANT_SHOPPING" || e.Outcome != "denied" {
					t.Errorf("%+v", e)
				}
			},
		},
		{
			reflexdomain.KindAlert, `{"attention":"ALERT","id":"a1","rule":"pc.tools.drift","severity":"HIGH","state":"OPEN","subjects":[{"type":"connection","id":"` + conn + `"},{"type":"planet","id":"x"}],"test":true}`,
			func(t *testing.T, e feed.Event) {
				if !e.Test || e.Attrs["rule"] != "pc.tools.drift" || len(e.Subjects) != 1 {
					t.Errorf("%+v", e)
				}
			},
		},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			e, err := feed.Normalize(tc.kind, "gateway", "gw1", at, []byte(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			if e.Kind != tc.kind || e.ActorType != "gateway" || e.ActorID != "gw1" || !e.OccurredAt.Equal(at) {
				t.Errorf("header %+v", e)
			}
			tc.check(t, e)
		})
	}
}

func TestNormalizeUnknownKindPassesThrough(t *testing.T) {
	e, err := feed.Normalize("future.kind", "system", "s", at, []byte(`{"secret":"x","agent":"`+agent+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	if e.Kind != "future.kind" || e.ActorID != "s" || len(e.Subjects) != 0 || len(e.Attrs) != 0 {
		t.Errorf("unknown kind kept more than kind and actor: %+v", e)
	}
	if feed.Known("future.kind") || !feed.Known("audit.anything") || !feed.Known("receipt.decision") {
		t.Error("Known")
	}
}

func TestNormalizeMalformed(t *testing.T) {
	e, err := feed.Normalize("receipt.decision", "gateway", "g", at, []byte(`not json`))
	if !errors.Is(err, feed.ErrMalformed) {
		t.Fatalf("err = %v", err)
	}
	if e.Kind != "receipt.decision" || e.Decision != "" {
		t.Errorf("%+v", e)
	}
}

func TestNormalizeBoundsAttributes(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"name":"x.y","outcome":"success","details":{`)
	for i := range 40 {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`"k` + strings.Repeat("a", i) + `":"v"`)
	}
	b.WriteString(`,"long":"` + strings.Repeat("x", 600) + `"}}`)
	e, err := feed.Normalize("audit.x.y", "user", "u", at, []byte(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Attrs) > feed.MaxAttrs {
		t.Errorf("%d attributes", len(e.Attrs))
	}
	if _, ok := e.Attrs["long"]; ok {
		t.Error("an over-long value survived")
	}
}
