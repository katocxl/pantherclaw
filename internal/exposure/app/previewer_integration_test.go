// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/exposure/app"
	"github.com/katocxl/pantherclaw/internal/exposure/exposuretest"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

type edition billing.Edition

func (e edition) Current(context.Context) (billing.Entitlements, error) {
	return billing.Entitlements{Edition: billing.Edition(e)}, nil
}

// TestIntReachPreviewer: the port previews containment and revocation on
// live data: DENY_ALL on the agent removes its effective reach and names
// the agent whose recent work it disrupts, HOLD_WRITES keeps reads and
// makes writes conditional, and the credential reach stays; Community gets
// EDITION_REQUIRED and nothing names an unknown subject.
func TestIntReachPreviewer(t *testing.T) {
	o := exposuretest.New(t)
	o.Grant(t, o.Agent, 0, "", "payments.*")
	o.Credential(t, "1 day")
	o.Dispatch(t, "payments.refund.get")
	p := &app.Previewer{Pool: o.P, Ents: edition(billing.Team)}
	ctx := context.Background()
	agent := reflexdomain.Subject{Type: reflexdomain.SubjectAgent, ID: o.Agent.String()}

	d, err := p.PreviewReduction(ctx, o.Org, reflexdomain.ReductionChange{
		Kind: app.KindContain, Control: reflexdomain.ControlDenyAll,
		Subjects: []reflexdomain.Subject{agent},
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.Before.Usable == 0 || d.After.Usable >= d.Before.Usable || d.After.Uncertain == 0 || len(d.Disruption) != 1 ||
		d.Disruption[0] != agent || !strings.Contains(d.Note, "credential view") {
		t.Fatalf("deny all: %+v", d)
	}
	h, err := p.PreviewReduction(ctx, o.Org, reflexdomain.ReductionChange{
		Kind: app.KindContain, Control: reflexdomain.ControlHoldWrites,
		Subjects: []reflexdomain.Subject{agent},
	})
	if err != nil {
		t.Fatal(err)
	}
	if h.After.Conditional <= h.Before.Conditional || len(h.Disruption) != 0 {
		t.Fatalf("hold writes: %+v", h)
	}
	r, err := p.PreviewReduction(ctx, o.Org, reflexdomain.ReductionChange{
		Kind:     app.KindRevokeCredential,
		Subjects: []reflexdomain.Subject{{Type: reflexdomain.SubjectConnection, ID: o.Conn.String()}},
	})
	if err != nil || r.After.Uncertain >= r.Before.Uncertain {
		t.Fatalf("revoke credential: %+v %v", r, err)
	}
	if _, err := p.PreviewReduction(ctx, o.Org, reflexdomain.ReductionChange{Kind: "explode", Subjects: []reflexdomain.Subject{agent}}); !errors.Is(err, app.ErrChange) {
		t.Fatalf("unknown kind: %v", err)
	}
	community := &app.Previewer{Pool: o.P, Ents: edition(billing.Community)}
	if _, err := community.PreviewReduction(ctx, o.Org, reflexdomain.ReductionChange{
		Kind:    app.KindContain,
		Control: reflexdomain.ControlDenyAll, Subjects: []reflexdomain.Subject{agent},
	}); !errors.Is(err, app.ErrEdition) {
		t.Fatalf("community: %v", err)
	}
	if _, err := (&app.Previewer{Pool: o.P}).PreviewReduction(ctx, o.Org, reflexdomain.ReductionChange{}); !errors.Is(err, app.ErrEdition) {
		t.Fatalf("no entitlements: %v", err)
	}
}
