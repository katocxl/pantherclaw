// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"context"
	"slices"
	"testing"

	detengine "github.com/katocxl/pantherclaw/internal/detection/engine"
	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	hubdomain "github.com/katocxl/pantherclaw/internal/hub/domain"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/protect"
	reflexapp "github.com/katocxl/pantherclaw/internal/reflex/app"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// crContain is a customer's automation that suspends the run a raised alert
// of its custom rule names.
const crContain = `apiVersion: automations.pantherclaw.dev/v1
kind: Automation
purpose: "Suspend the run a customer's delegation rule names."
work_kind: SECURITY_WORK
when:
  event:
    on: alert.raised
    where: event.attrs["rule"] == "org.range.delegated_incident"
    params:
      signal: {from: attrs.id, type: uuid}
  dedupe:
    key: "{{params.signal}}"
    window: 1d
authority:
  principal: self
  platform:
    - step: contain
      scopes: [TRIGGER_RUN]
    - step: open_case
      scopes: [TRIGGER_SUBJECTS]
do:
  - id: contain
    step: contain
    with:
      action: SUSPEND_RUN
      subject: TRIGGER_RUN
  - id: case
    step: open_case
    with:
      title: "Look at signal {{params.signal}}"
finish_when:
  - step: case
    condition: CASE_OPENED
limits:
  deadline: 1h
`

// crRequests stands in for the change ceremony: the test confirms through
// the Gate as the second person.
type crRequests struct{}

func (crRequests) Open(context.Context, db.TenantTx, protect.Request) (ids.UUID, error) {
	return ids.NewV7(), nil
}

func (crRequests) Void(context.Context, db.TenantTx, ids.UUID, string) error { return nil }

func (crRequests) Pending(context.Context, db.TenantTx, ids.UUID) (bool, error) { return true, nil }

// TestRange_ScenariosConfirmedCustomRules runs a customer's contain
// automation on the alerts of a customer's custom rule, through the real
// detection engine, triggers and automation engine (T-288). Unconfirmed, the
// rule's alert is INFERRED and the contain step skips; once a second person
// confirmed the published version, its alert is RULE_MATCH and the step
// suspends the run the alert names; withdrawn, it skips again. It is part of
// `task range`.
//
// Covers: F951
func TestRange_ScenariosConfirmedCustomRules(t *testing.T) {
	for _, tc := range []struct {
		name              string
		confirm, withdraw bool
		want              string
	}{
		{"unconfirmed", false, false, "SKIPPED"},
		{"confirmed", true, false, "DONE"},
		{"withdrawn", true, true, "SKIPPED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newPBRange(t, hubdomain.AutomationBody{AutomationName: "range-confirmed-contain", Definition: crContain})
			det, gate, second := crConfirmable(t, r)
			author := r.f.As(td.KindUser, td.RoleSecurityAdmin)
			c, err := det.CreateCustomRule(author, pbIncidentRule)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := det.PublishCustomRule(author, c.Custom.ID); err != nil {
				t.Fatal(err)
			}
			if tc.confirm {
				held, err := det.RequestCustomRuleConfirmation(author, "org.range.delegated_incident", 1, "reviewed with the team")
				if err != nil {
					t.Fatal(err)
				}
				r.f.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
					return gate.Apply(ctx, tx, held.Request, []ids.UUID{second})
				})
			}
			if tc.withdraw {
				if err := det.WithdrawCustomRuleConfirmation(author, "org.range.delegated_incident", "no longer reviewed"); err != nil {
					t.Fatal(err)
				}
			}
			x := r.produce(t, grantsapp.DelegatedEvent(pbInstance, pbChild, pbParent, 1, pbRun))
			r.drive(t, x)
			if st := r.step(t, x, "contain"); st != tc.want {
				t.Fatalf("contain: %s, want %s", st, tc.want)
			}
			scopes := r.container.scopes()
			if tc.want == "DONE" && !slices.Equal(scopes, []string{string(reflexdomain.SubjectRun) + ":" + pbRun.String()}) {
				t.Fatalf("contained %v, want the alert's run", scopes)
			}
			if tc.want != "DONE" && len(scopes) != 0 {
				t.Fatalf("contained %v on an unconfirmed rule", scopes)
			}
		})
	}
}

// crConfirmable gives the fixture's person detection.manage, adds a second
// security admin and returns the detections service with the Gate.
func crConfirmable(t *testing.T, r *pbRange) (*reflexapp.Detections, *protect.Gate, ids.UUID) {
	t.Helper()
	second := ids.NewV7()
	r.f.Exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'second')", r.f.Org, second)
	for _, u := range []ids.UUID{r.f.User, second} {
		r.f.Exec(t, `INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by) VALUES ($1, $2, $3, $4, 'ORG', 'test')`,
			r.f.Org, ids.NewV7(), string(td.RoleSecurityAdmin), u)
	}
	env, err := detengine.NewEnv(celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	gate := &protect.Gate{Requests: crRequests{}}
	det := &reflexapp.Detections{Pool: r.f.Pool, Env: env, Ents: pbEnts}
	det.RegisterProtect(gate)
	return det, gate, second
}
