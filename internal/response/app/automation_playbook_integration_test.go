// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	rapp "github.com/katocxl/pantherclaw/internal/response/app"
	rdomain "github.com/katocxl/pantherclaw/internal/response/domain"
)

// TestHR284_AnAutomationContainsOnlyARunAsAPlaybook: a governed
// automation's contain step is a playbook, never SOAR (G0 M11 part 2 D61):
// the response action records the automation as its actor and PLAYBOOK as
// its source, it may only DENY_ALL a run, and its idempotency key returns
// the same action for the same execution and step.
func TestHR284_AnAutomationContainsOnlyARunAsAPlaybook(t *testing.T) {
	w := newWorld(t, "ENFORCED")
	auto := ids.NewV7()
	actor := reflexdomain.Subject{Type: reflexdomain.SubjectAutomation, ID: auto.String()}
	run := reflexdomain.Subject{Type: reflexdomain.SubjectRun, ID: w.run.String()}
	key := "auto:" + ids.NewV7().String() + ":contain"

	for _, c := range []struct {
		scope   reflexdomain.Subject
		control string
	}{
		{run, reflexdomain.ControlHoldWrites},
		{reflexdomain.Subject{Type: reflexdomain.SubjectGrant, ID: w.grant.String()}, reflexdomain.ControlDenyAll},
		{reflexdomain.Subject{Type: reflexdomain.SubjectAgent, ID: w.agent.String()}, reflexdomain.ControlDenyAll},
		{reflexdomain.Subject{Type: reflexdomain.SubjectUser, ID: w.alice.String()}, reflexdomain.ControlDenyAll},
		{reflexdomain.Subject{Type: reflexdomain.SubjectConnection, ID: w.conn.String()}, reflexdomain.ControlDenyAll},
	} {
		if _, err := w.contain(reflexdomain.ContainRequest{Scope: c.scope, Control: c.control, Actor: actor}); !errors.Is(err, rapp.ErrPlaybookScope) {
			t.Errorf("an automation on %s %s: %v", c.scope.Type, c.control, err)
		}
	}

	res, err := w.contain(reflexdomain.ContainRequest{Scope: run, Control: reflexdomain.ControlDenyAll, Actor: actor, Idempotency: key})
	if err != nil {
		t.Fatalf("an automation suspending the triggering run: %v", err)
	}
	a := w.action(res.ActionID)
	if a.Source != rdomain.SourcePlaybook || a.Actor != "automation:"+auto.String() {
		t.Fatalf("action source %s actor %s", a.Source, a.Actor)
	}
	again, err := w.contain(reflexdomain.ContainRequest{Scope: run, Control: reflexdomain.ControlDenyAll, Actor: actor, Idempotency: key})
	if err != nil || again.ActionID != res.ActionID {
		t.Fatalf("the same step again: %+v %v", again, err)
	}
	// A malformed automation id is no actor at all.
	bad := reflexdomain.Subject{Type: reflexdomain.SubjectAutomation, ID: "not-an-id"}
	if _, err := w.contain(reflexdomain.ContainRequest{Scope: run, Control: reflexdomain.ControlDenyAll, Actor: bad}); !errors.Is(err, rapp.ErrActor) {
		t.Fatalf("a malformed automation actor: %v", err)
	}
}
