// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ratelimit"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

type downLimiter struct{}

func (downLimiter) Take(context.Context, string, string, time.Duration, int, int) (ratelimit.Decision, error) {
	return ratelimit.Decision{}, errors.New("store down")
}

// TestHR490_AReplayCounterErrorIsLoggedAndRefuses: a counter error refuses
// the replay (HR-376) and says so in the log, so an outage does not read as
// a caller over the limit.
// Covers: HR-490
func TestHR490_AReplayCounterErrorIsLoggedAndRefuses(t *testing.T) {
	var out bytes.Buffer
	l := &replayLimiter{limiter: downLimiter{}, window: time.Minute, log: slog.New(slog.NewTextHandler(&out, nil))}
	if l.allow(context.Background(), tenancy.Caller{}) {
		t.Fatal("a counter error admitted a replay")
	}
	if !strings.Contains(out.String(), "evidence.replay_rate_unavailable") {
		t.Fatalf("no log line: %q", out.String())
	}
}
