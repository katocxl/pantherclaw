// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package transactionsrpc

import (
	"encoding/base64"
	"encoding/json/v2"
	"strings"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

var coverageStates = map[string]pantherclawv1.CoverageState{
	"UNKNOWN": pantherclawv1.CoverageState_COVERAGE_STATE_UNKNOWN, "OBSERVE_ONLY": pantherclawv1.CoverageState_COVERAGE_STATE_OBSERVE_ONLY,
	"PARTIAL": pantherclawv1.CoverageState_COVERAGE_STATE_PARTIAL, "ENFORCED": pantherclawv1.CoverageState_COVERAGE_STATE_ENFORCED,
}

// coverageOf reads the coverage claim from a decision receipt's signed
// payload (HR-217, PAP-1 §9.1); nil when it has none, or its body was
// removed by retention. A claim the receipt says was unavailable has
// only its reason. It is shown, not trusted: verifiers check the
// receipt's signature and the snapshot ledger.
func coverageOf(jws string) *pantherclawv1.DecisionCoverage {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var r struct {
		Pap struct {
			Coverage *struct {
				Unavailable   string   `json:"unavailable"`
				State         string   `json:"state"`
				Snapshot      string   `json:"snapshot"`
				SnapshotState string   `json:"snapshot_state"`
				Lapsed        bool     `json:"lapsed"`
				Reason        string   `json:"reason"`
				Exclusions    []string `json:"exclusions"`
			} `json:"coverage"`
		} `json:"pap"`
	}
	if json.Unmarshal(payload, &r) != nil || r.Pap.Coverage == nil {
		return nil
	}
	c := r.Pap.Coverage
	if c.Unavailable != "" {
		return &pantherclawv1.DecisionCoverage{Unavailable: c.Unavailable}
	}
	return &pantherclawv1.DecisionCoverage{
		State: coverageStates[c.State], SnapshotId: c.Snapshot, SnapshotState: coverageStates[c.SnapshotState],
		Lapsed: c.Lapsed, Reason: c.Reason, ExclusionIds: c.Exclusions,
	}
}
