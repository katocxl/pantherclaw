// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"errors"
	"fmt"
	"time"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	rtapp "github.com/katocxl/pantherclaw/internal/redteam/app"
	rtdomain "github.com/katocxl/pantherclaw/internal/redteam/domain"
)

// Customer-authored scenarios (G0 M17 D124–D126, PN-009.6): CX-### files a
// customer writes for its own tools. A range runs library scenarios or
// customer ones, never both; a customer range has no assurance report, only
// the unsigned summary marked customer-authored, and its baseline is an
// earlier customer range named by its id.

// customerStatement is the summary's statement for a customer range.
const customerStatement = "Customer-authored scenarios against simulated targets, recorded by this runner. Unsigned. " +
	"Not a PantherClaw-attested assurance report and not a compliance certification."

// setOrigin is the one origin of a scenario set.
func setOrigin(set []rtapp.Loaded) (string, error) {
	origin := ""
	for _, l := range set {
		o := rtdomain.OriginOf(l.Scenario.ID)
		if origin != "" && o != origin {
			return "", errors.New("a range runs library (RT-###) or customer (CX-###) scenarios, not both: split the directory")
		}
		origin = o
	}
	return origin, nil
}

// checkCustomerEdition refuses customer scenarios early on a plan below
// Business. A plan the caller cannot read is left to the server, which
// checks every range anyway.
func checkCustomerEdition(ctx context.Context, c clients) error {
	if c.entitlements == nil {
		return nil
	}
	res, err := c.entitlements.GetEntitlements(ctx, &pantherclawv1.GetEntitlementsRequest{})
	if err != nil {
		return nil //nolint:nilerr // the server is the gate; this check only fails early
	}
	switch e := res.GetEntitlements().GetEdition(); e {
	case "community", "team":
		return fmt.Errorf("EDITION_REQUIRED: customer scenarios (CX-###) need the Business edition; this org has %s", e)
	}
	return nil
}

// loadRangeBaseline reads an earlier finished customer range as the
// baseline of a customer range (D126).
func loadRangeBaseline(ctx context.Context, c clients, id string) (*baseline, error) {
	if !uuidRe.MatchString(id) {
		return nil, errors.New("--baseline-range must be a range id")
	}
	res, err := c.ranges.GetRange(ctx, &pantherclawv1.GetRangeRequest{RangeId: id})
	if err != nil {
		return nil, errors.New(describe(err))
	}
	r := res.GetRange()
	switch {
	case r.GetState() != pantherclawv1.RangeState_RANGE_STATE_FINISHED:
		return nil, fmt.Errorf("BASELINE_INVALID: range %s has not finished", id)
	case r.GetOrigin() != rtdomain.OriginCustomer:
		return nil, fmt.Errorf("BASELINE_INVALID: range %s is not a customer range; a library range's baseline is its assurance pack (--baseline)", id)
	}
	b := &baseline{rangeID: r.GetId(), finished: r.GetFinishTime().AsTime().UTC().Format(time.RFC3339)}
	for _, s := range res.GetResults() {
		b.entries = append(b.entries, rtdomain.Entry{ID: s.GetScenarioId(), Digest: s.GetScenarioDigest(), Verdict: verdictOf(s.GetVerdict())})
	}
	if len(b.entries) == 0 {
		return nil, fmt.Errorf("BASELINE_INVALID: range %s holds no results", id)
	}
	return b, nil
}

// verdictOf is a recorded verdict as the baseline gate compares it.
func verdictOf(v pantherclawv1.RangeVerdict) rtdomain.Verdict {
	switch v {
	case pantherclawv1.RangeVerdict_RANGE_VERDICT_PASS:
		return rtdomain.VerdictPass
	case pantherclawv1.RangeVerdict_RANGE_VERDICT_FAIL:
		return rtdomain.VerdictFail
	case pantherclawv1.RangeVerdict_RANGE_VERDICT_SKIPPED:
		return rtdomain.VerdictSkipped
	case pantherclawv1.RangeVerdict_RANGE_VERDICT_MISSING:
		return rtdomain.VerdictMissing
	case pantherclawv1.RangeVerdict_RANGE_VERDICT_ERROR, pantherclawv1.RangeVerdict_RANGE_VERDICT_UNSPECIFIED:
		return rtdomain.VerdictError
	}
	return rtdomain.VerdictError
}
