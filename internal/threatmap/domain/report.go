// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/katocxl/pantherclaw/internal/threatmap/catalog"
)

// ReportFormat is the format of threat_map.json, the report a pack of scope
// threat_map holds (G0 M28 D720, HR-688).
const ReportFormat = "pantherclaw.threat-map/v1"

// Report is threat_map.json: a point-in-time evaluation with every input and
// mapping field the evaluator read, so an offline verifier re-derives every
// technique and tactic count from the report alone (D714c M2, D720).
type Report struct {
	Format    string            `json:"format"`
	Org       string            `json:"org"`
	Framework catalog.Framework `json:"framework"`
	// Scope is the environment the report covers, or the org.
	Scope         Scope             `json:"scope"`
	EvaluatedAt   time.Time         `json:"evaluated_at"`
	Statement     string            `json:"statement"`
	Catalog       ReportCatalog     `json:"catalog"`
	MappingDigest string            `json:"mapping_digest"`
	Inputs        Inputs            `json:"inputs"`
	Mapping       Mapping           `json:"mapping"`
	Techniques    []ReportTechnique `json:"techniques"`
	Tactics       []ReportTactic    `json:"tactics"`
}

// ReportCatalog names the pinned MITRE catalog the report was built with.
type ReportCatalog struct {
	Version string `json:"version"`
	Digest  string `json:"digest"`
}

// ReportTechnique is one technique or sub-technique: its status, its lanes
// and their reasons, and its gaps.
type ReportTechnique struct {
	ID      string        `json:"id"`
	Status  Status        `json:"status"`
	Prevent LaneState     `json:"prevent"`
	Detect  LaneState     `json:"detect"`
	Respond LaneState     `json:"respond"`
	Test    TestState     `json:"test"`
	Reasons ReportReasons `json:"reasons"`
	Gaps    []Gap         `json:"gaps"`
}

// ReportReasons are each lane's reasons.
type ReportReasons struct {
	Prevent []Reason `json:"prevent"`
	Detect  []Reason `json:"detect"`
	Respond []Reason `json:"respond"`
	Test    []Reason `json:"test"`
}

// ReportTactic is one tactic column's technique counts by status. There is
// no total across tactics.
type ReportTactic struct {
	ID     string       `json:"id"`
	Counts ReportCounts `json:"counts"`
}

// ReportCounts counts a tactic's techniques by status.
type ReportCounts struct {
	Evidenced int `json:"evidenced"`
	Partial   int `json:"partial"`
	Gap       int `json:"gap"`
	Outside   int `json:"outside"`
}

// NewReport is the report of org for m, the evaluation of mp and in.
func NewReport(org string, m Map, in Inputs, mp Mapping) Report {
	r := Report{
		Format: ReportFormat, Org: org, Framework: m.Framework, Scope: m.Scope, EvaluatedAt: m.EvaluatedAt.UTC(), Statement: m.Statement,
		Catalog: ReportCatalog{Version: m.CatalogVersion, Digest: m.CatalogDigest}, MappingDigest: m.MappingDigest,
		Inputs: in, Mapping: mp, Techniques: []ReportTechnique{}, Tactics: []ReportTactic{},
	}
	var add func(t Technique)
	add = func(t Technique) {
		gaps := t.Gaps
		if gaps == nil {
			gaps = []Gap{}
		}
		r.Techniques = append(r.Techniques, ReportTechnique{
			ID: t.ID, Status: t.Status, Prevent: t.Prevent.State, Detect: t.Detect.State, Respond: t.Respond.State, Test: t.Test.State,
			Reasons: ReportReasons{Prevent: reasons(t.Prevent.Reasons), Detect: reasons(t.Detect.Reasons), Respond: reasons(t.Respond.Reasons), Test: reasons(t.Test.Reasons)},
			Gaps:    gaps,
		})
		for _, s := range t.Subtechniques {
			add(s)
		}
	}
	for _, t := range m.Techniques {
		add(t)
	}
	for _, t := range m.Tactics {
		r.Tactics = append(r.Tactics, ReportTactic{ID: t.ID, Counts: ReportCounts{Evidenced: t.Evidenced, Partial: t.Partial, Gap: t.Gap, Outside: t.Outside}})
	}
	return r
}

func reasons(rs []Reason) []Reason {
	if rs == nil {
		return []Reason{}
	}
	return rs
}

// DecodeReport decodes threat_map.json strictly.
func DecodeReport(b []byte) (*Report, error) {
	var r Report
	if err := json.Unmarshal(b, &r, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("threat map report: %w", err)
	}
	if r.Format != ReportFormat {
		return nil, fmt.Errorf("threat map report: format %.64q", r.Format)
	}
	return &r, nil
}

// ErrOtherCatalog reports a report built with a MITRE catalog this build
// does not embed: it cannot be re-derived here.
var ErrOtherCatalog = errors.New("built with another MITRE catalog")

// Rederive re-runs Evaluate on the report's own inputs and mapping under
// this build's pinned catalog and returns the report that gives (HR-688).
// A report of an unknown framework, or of another catalog digest, is
// ErrOtherCatalog. A report the evaluator cannot read is an error, never a
// panic: an offline verifier reads untrusted files.
func (r *Report) Rederive() (out Report, err error) {
	if !slices.Contains(catalog.Frameworks(), r.Framework) {
		return Report{}, ErrOtherCatalog
	}
	cat := catalog.Load(r.Framework)
	if cat.Digest != r.Catalog.Digest {
		return Report{}, ErrOtherCatalog
	}
	defer func() {
		if p := recover(); p != nil {
			out, err = Report{}, fmt.Errorf("threat map report: the inputs do not evaluate: %v", p)
		}
	}()
	return NewReport(r.Org, Evaluate(cat, r.Mapping, r.Inputs), r.Inputs, r.Mapping), nil
}
