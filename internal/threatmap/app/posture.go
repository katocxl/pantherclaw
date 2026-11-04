// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	pvdomain "github.com/katocxl/pantherclaw/internal/postureview/domain"
	pvports "github.com/katocxl/pantherclaw/internal/postureview/ports"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	"github.com/katocxl/pantherclaw/internal/threatmap/catalog"
	"github.com/katocxl/pantherclaw/internal/threatmap/domain"
	"github.com/katocxl/pantherclaw/internal/threatmap/mapset"
)

// Posture finding kinds of the threat map source (G0 M28 D724); their
// severities are in postureview's fixed table.
const (
	KindRuleOff              = pvdomain.KindThreatMapRuleOff
	KindPlaybookNotInstalled = pvdomain.KindThreatMapPlaybookNotInstalled
	KindPlaybookDisabled     = pvdomain.KindThreatMapPlaybookDisabled
	KindTestFailed           = pvdomain.KindThreatMapTestFailed
)

// ErrPostureEdition: the source needs Team.
var ErrPostureEdition = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED",
	"Threat map gaps in the posture queue need Team or higher.")

// Source reports the threat map's fixable gaps to the ranked posture queue
// (D724): one finding per fix target (a rule, a Hub item, an automation, a
// scenario) with the techniques it leaves open. Route and edition gaps are
// not findings here: the coverage source and the plan page report them.
// Every finding is org-wide, so it needs org scope, and threatmap.read as
// well as posture.read.
type Source struct {
	Svc *Service
}

var _ pvports.Source = (*Source)(nil)

// Name implements ports.Source.
func (s *Source) Name() pvdomain.Source { return pvdomain.SourceThreatMap }

// target is one fix target and the techniques it leaves open.
type target struct {
	kind, id, title, label string
	fix                    pvdomain.FixKind
	techniques             []string
	// since is when the underlying fact began, when the row has it (G0
	// M28 D724a): a rule's disabled_at, a failing result's time. Zero
	// means the evaluation time.
	since time.Time
}

// Findings implements ports.Source.
func (s *Source) Findings(ctx context.Context, v pvports.Viewer, _ pvdomain.Filter) ([]pvdomain.Finding, bool, error) {
	if s.Svc == nil || s.Svc.Ents == nil {
		return nil, false, ErrPostureEdition
	}
	e, err := s.Svc.Ents.Current(ctx)
	if err != nil {
		return nil, false, err
	}
	if !e.ThreatMapExport() {
		return nil, false, ErrPostureEdition
	}
	reach := v.Posture
	if v.Under != nil {
		r, err := v.Under(ctx, td.PermThreatMapRead)
		if err != nil {
			return nil, false, err
		}
		reach = reach.Intersect(r)
	}
	if !reach.Has(nil) {
		return nil, false, td.ErrPermissionDenied(td.PermThreatMapRead)
	}
	now := s.Svc.now()
	targets := map[string]*target{}
	err = s.Svc.Pool.InTenantTx(ctx, v.Org, func(ctx context.Context, tx db.TenantTx) error {
		rec, err := s.Svc.Store.Records(ctx, tx, v.Org, now)
		if err != nil {
			return err
		}
		for _, f := range catalog.Frameworks() {
			in, err := inputsFor(ctx, s.Svc.Store, tx, v.Org, rec, f, domain.Scope{}, e, now)
			if err != nil {
				return err
			}
			disabledAt := map[string]time.Time{}
			for _, r := range in.Rules {
				disabledAt[r.ID] = r.DisabledAt
			}
			for _, t := range domain.Evaluate(catalog.Load(f), mapset.Evaluator(f), in).Techniques {
				collect(targets, t, disabledAt)
				for _, sub := range t.Subtechniques {
					collect(targets, sub, disabledAt)
				}
			}
		}
		return nil
	}, db.ReadOnly(), db.RepeatableRead())
	if err != nil {
		return nil, false, err
	}
	keys := make([]string, 0, len(targets))
	for k := range targets {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	out := make([]pvdomain.Finding, 0, min(len(keys), pvdomain.MaxPerSource))
	for _, k := range keys {
		if len(out) == pvdomain.MaxPerSource {
			return out, true, nil
		}
		out = append(out, finding(targets[k], now))
	}
	return out, false, nil
}

func add(targets map[string]*target, t target, technique string) {
	key := t.kind + ":" + t.id
	cur, ok := targets[key]
	if !ok {
		cur = &t
		targets[key] = cur
	}
	if !slices.Contains(cur.techniques, technique) {
		cur.techniques = append(cur.techniques, technique)
	}
	// The earliest known start, should two rows of one target differ.
	if !t.since.IsZero() && (cur.since.IsZero() || t.since.Before(cur.since)) {
		cur.since = t.since
	}
}

// collect adds a technique's fix targets; disabledAt is each rule's
// disabled_at (D724a).
func collect(targets map[string]*target, t domain.Technique, disabledAt map[string]time.Time) {
	for _, r := range t.Detect.Rules {
		if r.Reason == domain.ReasonRuleOff && (r.Source == domain.SourceBuiltin || r.Source == domain.SourceHub) {
			add(targets, target{
				kind: KindRuleOff, id: "detection_rule:" + r.RuleID, title: "A detection rule mapped to MITRE techniques is off",
				label: "Turn rule " + r.RuleID + " back on", fix: pvdomain.FixEnableRule, since: disabledAt[r.RuleID],
			}, t.ID)
		}
	}
	for _, a := range t.Respond.Automations {
		switch a.Reason { //nolint:exhaustive // only these two reasons have a queue fix (D724)
		case domain.ReasonPlaybookNotInstalled:
			add(targets, target{
				kind: KindPlaybookNotInstalled, id: "hub_item:" + a.Name, title: "A Hub playbook responds to a mapped rule and is not installed",
				label: "Install Hub playbook " + a.Name, fix: pvdomain.FixInstallHubItem,
			}, t.ID)
		case domain.ReasonPlaybookDisabled:
			add(targets, target{
				kind: KindPlaybookDisabled, id: "automation:" + a.ID, title: "An automation that responds to a mapped rule is not active",
				label: "Turn on automation " + a.Name, fix: pvdomain.FixEnableAutomation,
			}, t.ID)
		}
	}
	for _, sc := range t.Test.Scenarios {
		if sc.State == domain.TestFailed {
			add(targets, target{
				kind: KindTestFailed, id: "scenario:" + sc.ScenarioID, title: "A library scenario mapped to MITRE techniques failed",
				label: "Run scenario " + sc.ScenarioID + " again after the fix", fix: pvdomain.FixRunRange, since: sc.RecordedAt,
			}, t.ID)
		}
	}
}

// maxListed is how many technique ids a finding's detail names.
const maxListed = 10

func finding(t *target, now time.Time) pvdomain.Finding {
	slices.Sort(t.techniques)
	ids := t.techniques
	list := strings.Join(ids, ", ")
	if len(ids) > maxListed {
		list = strings.Join(ids[:maxListed], ", ") + fmt.Sprintf(" and %d more", len(ids)-maxListed)
	}
	since := now
	if !t.since.IsZero() {
		since = t.since
	}
	return pvdomain.Finding{
		Source: pvdomain.SourceThreatMap, SourceID: t.id, Kind: t.kind, Title: t.title,
		Detail: map[string]string{"techniques": list}, State: "OPEN", Since: since,
		Fix: pvdomain.Fix{Kind: t.fix, TargetID: t.id, Label: t.label},
	}
}
