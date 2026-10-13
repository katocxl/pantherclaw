// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/transactions/domain"
	pcgithub "github.com/katocxl/pantherclaw/packages/pc-github"
)

// TestHR206_EachDeploymentStatusMeansWhatTheCoordinatorDecided (G0 M8
// W1c, coordinator decision 2026-10-13): pc.github's deployment verifier
// reads GitHub's latest status. Success and inactive (it deployed, then
// was replaced) confirm it; queued, pending and in progress are pending; a
// failure or an error only asks a person, since evidence never shows that
// something did not happen (HR-192); so does nothing found by the window's
// end; a failed read is inconclusive and read again. A person may release
// the question as not occurred with a security key.
func TestHR206_EachDeploymentStatusMeansWhatTheCoordinatorDecided(t *testing.T) {
	p, err := manifest.Decode(pcgithub.Package)
	if err != nil {
		t.Fatal(err)
	}
	d, _ := p.Definition("github.deployment.trigger")
	v := d.Verifier
	start := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	within, after := start.Add(time.Minute), start.Add(2*time.Hour)
	for _, c := range []struct {
		name       string
		o          domain.Observation
		state      domain.EffectState
		final, ask bool
		occurred   bool
	}{
		{"success", domain.Observation{HTTPStatus: 200, Found: true, Complete: true, Fields: map[string]string{"/0/state": "success"}, At: within}, domain.Confirmed, true, false, true},
		{"inactive", domain.Observation{HTTPStatus: 200, Found: true, Complete: true, Fields: map[string]string{"/0/state": "inactive"}, At: within}, domain.Confirmed, true, false, true},
		{"queued", domain.Observation{HTTPStatus: 200, Found: true, Complete: true, Fields: map[string]string{"/0/state": "queued"}, At: within}, domain.PropagationPending, false, false, true},
		{"pending", domain.Observation{HTTPStatus: 200, Found: true, Complete: true, Fields: map[string]string{"/0/state": "pending"}, At: within}, domain.PropagationPending, false, false, true},
		{"in_progress", domain.Observation{HTTPStatus: 200, Found: true, Complete: true, Fields: map[string]string{"/0/state": "in_progress"}, At: within}, domain.PropagationPending, false, false, true},
		{"failure", domain.Observation{HTTPStatus: 200, Found: true, Complete: true, Fields: map[string]string{"/0/state": "failure"}, At: within}, "", true, true, false},
		{"error", domain.Observation{HTTPStatus: 200, Found: true, Complete: true, Fields: map[string]string{"/0/state": "error"}, At: within}, "", true, true, false},
		{"none yet", domain.Observation{HTTPStatus: 200, Complete: true, At: within}, domain.PropagationPending, false, false, false},
		{"none by the deadline", domain.Observation{HTTPStatus: 200, Complete: true, At: after}, "", true, true, false},
		{"a cut listing", domain.Observation{HTTPStatus: 200, At: after}, "", false, false, false},
		{"a failed read", domain.Observation{HTTPStatus: 502, At: within}, "", false, false, false},
	} {
		a := domain.Assess(v, domain.PurposeConsequence, nil, c.o, start)
		if a.State != c.state || a.Final != c.final || a.NeedsPerson != c.ask || a.Occurred() != c.occurred {
			t.Errorf("%s: %+v (occurred %v)", c.name, a, a.Occurred())
		}
		if a.State == domain.NoneConfirmed {
			t.Errorf("%s: evidence said it did not happen", c.name)
		}
	}
	if err := domain.CheckReleasable(domain.KindConsequenceUnconfirmed, domain.TaskOpen); err != nil {
		t.Fatalf("a person releases an unconfirmed consequence: %v", err)
	}
}
