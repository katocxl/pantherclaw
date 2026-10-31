// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"crypto/rand"
	"math/big"
	"slices"
	"time"

	"github.com/katocxl/pantherclaw/internal/redteam/domain"
)

// resubmits bounds the extra sends of one call, and resubmitWait is the most
// a resubmit waits, times its number.
const (
	resubmits    = 8
	resubmitWait = 100 * time.Millisecond
)

// Resubmit sends one call of a concurrent step and, when the step names
// retry_on, sends it again while the answer carries that reason, as an agent
// told BUDGET_BUSY may (HR-505): the budget was too contended to reserve, so
// nothing was reserved. The attempt number starts at 0. The last answer is
// the call's observation, so a call still busy after the bound fails the
// step's expectation, and max_allow still counts every final ALLOW.
func Resubmit(ctx context.Context, retryOn string, call func(attempt int) (domain.Observation, error)) (domain.Observation, error) {
	for attempt := 0; ; attempt++ {
		o, err := call(attempt)
		if err != nil || retryOn == "" || attempt == resubmits || !answered(o, retryOn) {
			return o, err
		}
		select {
		case <-ctx.Done():
			return o, ctx.Err()
		case <-time.After(jitter(time.Duration(attempt+1) * resubmitWait)):
		}
	}
}

// jitter is a random wait of at most most, so calls that lost together do not
// meet again.
func jitter(most time.Duration) time.Duration {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(most)))
	if err != nil {
		return most
	}
	return time.Duration(n.Int64())
}

func answered(o domain.Observation, reason string) bool {
	return o.Reason == reason || o.Code == reason || slices.Contains(o.Reasons, reason)
}
