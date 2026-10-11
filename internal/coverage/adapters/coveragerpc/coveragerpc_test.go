// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package coveragerpc_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/coverage/adapters/coveragerpc"
	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// TestFreshnessContractIsPublished: the contract states the configured
// expiry, every invalidating change and that stale reads are PARTIAL
// (F440).
func TestFreshnessContractIsPublished(t *testing.T) {
	f, err := domain.NewFreshness(6*time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	res, err := coveragerpc.New(f).GetFreshnessContract(context.Background(), &pantherclawv1.GetFreshnessContractRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if res.GetEnforcedTtl().AsDuration() != 6*time.Hour || res.GetReassessInterval().AsDuration() != time.Minute {
		t.Errorf("durations %v, %v", res.GetEnforcedTtl().AsDuration(), res.GetReassessInterval().AsDuration())
	}
	if len(res.GetInvalidationKinds()) != len(domain.InvalidationKinds)-2 || slices.Contains(res.GetInvalidationKinds(), "exclusion") {
		t.Errorf("invalidation kinds %v", res.GetInvalidationKinds())
	}
	if res.GetStaleState() != pantherclawv1.CoverageState_COVERAGE_STATE_PARTIAL {
		t.Errorf("stale state %v", res.GetStaleState())
	}
}
