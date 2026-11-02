// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"slices"
	"strings"
	"testing"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
)

const onInferred = `
apiVersion: automations.pantherclaw.dev/v1
kind: Automation
purpose: Answer an inferred alert.
work_kind: SECURITY_WORK
review_by: "2026-12-01"
when:
  TRIGGER
authority:
  principal: self
  platform:
    - step: contain
      scopes: [TRIGGER_RUN]
    - step: revoke_grant
      scopes: [TRIGGER_GRANT, EXECUTION]
    - step: open_case
      scopes: [TRIGGER_SUBJECTS]
  revocable:
    all: true
do:
  - id: act
    STEP
  - id: case
    step: open_case
    with:
      title: Look at this signal
finish_when:
  - step: case
    condition: CASE_OPENED
limits:
  deadline: 1h
`

const (
	eventOnInferred     = "event:\n    on: alert.inferred"
	thresholdOnInferred = "threshold:\n    on: alert.inferred\n    over: 1h\n    at_least: 3"
	eventOnRaised       = "event:\n    on: alert.raised"
	contains            = "step: contain\n    with:\n      action: SUSPEND_RUN\n      subject: TRIGGER_RUN"
	revokesTrigger      = "step: revoke_grant\n    with:\n      scope: TRIGGER_GRANT"
	revokesOwn          = "step: revoke_grant\n    with:\n      scope: EXECUTION"
	opensCase           = "step: open_case\n    with:\n      title: A person looks"
)

func inferredDoc(trigger, step string) string {
	doc := strings.NewReplacer("TRIGGER\n", trigger+"\n", "STEP\n", step+"\n").Replace(onInferred)
	if step != revokesTrigger {
		// authority.revocable is declared only by a step that revokes beyond
		// its execution.
		doc = strings.Replace(doc, "  revocable:\n    all: true\n", "", 1)
	}
	return doc
}

// TestHR640_ValidationRefusesContainOnAnInferredAlert: a definition that
// starts from an inferred alert can't name a step that would contain, as an
// event or a threshold, in `do` or in compensation. Opening a case or
// revoking its own grants stays valid, and so does contain on a raised
// alert, where the step itself skips an inferred one. Covers: F933
func TestHR640_ValidationRefusesContainOnAnInferredAlert(t *testing.T) {
	env := fakeEnv{edition: autodomain.EditionBusiness, approvers: 1}
	for _, tc := range []struct {
		name, trigger, step string
		refused             bool
	}{
		{"contain on an inferred event", eventOnInferred, contains, true},
		{"contain on an inferred threshold", thresholdOnInferred, contains, true},
		{"revoking the trigger's grant", eventOnInferred, revokesTrigger, true},
		{"revoking its own grants", eventOnInferred, revokesOwn, false},
		{"opening a case", eventOnInferred, opensCase, false},
		{"contain on a raised alert", eventOnRaised, contains, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := codes(validate(t, inferredDoc(tc.trigger, tc.step), env))
			if slices.Contains(got, autodomain.CodeContainOnInferred) != tc.refused {
				t.Fatalf("errors = %v, want refused %v", got, tc.refused)
			}
			if !tc.refused && len(got) != 0 {
				t.Fatalf("errors = %v", got)
			}
		})
	}

	compensation := strings.Replace(inferredDoc(eventOnInferred, opensCase), "limits:\n",
		"if_fails:\n  compensate:\n    - id: undo\n      step: contain\n      with:\n        action: SUSPEND_RUN\n        subject: TRIGGER_RUN\nlimits:\n", 1)
	if got := codes(validate(t, compensation, env)); !slices.Contains(got, autodomain.CodeContainOnInferred) {
		t.Fatalf("compensation: errors = %v", got)
	}
}

// TestHR640_ContainsNamesEveryStepThatWouldContain is what the threshold
// loop asks a definition. Covers: F933
func TestHR640_ContainsNamesEveryStepThatWouldContain(t *testing.T) {
	for step, want := range map[string]bool{contains: true, revokesTrigger: true, revokesOwn: false, opensCase: false} {
		d, err := autodomain.Parse([]byte(inferredDoc(eventOnRaised, step)))
		if err != nil {
			t.Fatal(err)
		}
		if got := d.Contains(); got != want {
			t.Errorf("%q: Contains = %v, want %v", step, got, want)
		}
	}
}
