// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"errors"
	"time"

	apapp "github.com/katocxl/pantherclaw/internal/approvals/app"
	"github.com/katocxl/pantherclaw/internal/platform/config"
)

// WaitlistConfig bounds the wait handles of one API server (G0 M5 part 2,
// HR-174). Hold deadlines and consume windows are per-org waitlist
// settings, which can only shorten the defaults (decision 6).
type WaitlistConfig struct {
	// MaxWaitsPerInstance and MaxWaits bound concurrent waits per agent
	// instance and per server; beyond them a wait answers
	// WAIT_LIMIT_REACHED.
	MaxWaitsPerInstance int `json:"max_waits_per_instance" env:"PC_WAITLIST_MAX_WAITS_PER_INSTANCE"`
	MaxWaits            int `json:"max_waits" env:"PC_WAITLIST_MAX_WAITS"`
	// LongPollMax caps one Wait call (at most 30 seconds).
	LongPollMax config.Duration `json:"long_poll_max" env:"PC_WAITLIST_LONG_POLL_MAX"`
}

func defaultWaitlist() WaitlistConfig {
	return WaitlistConfig{
		MaxWaitsPerInstance: apapp.DefaultWaitsPerInstance, MaxWaits: apapp.DefaultWaitsPerServer,
		LongPollMax: config.Duration(apapp.LongPollMax),
	}
}

func (c *Config) validateM5p2() []error {
	w := c.Waitlist
	var errs []error
	if w.MaxWaitsPerInstance < 1 || w.MaxWaitsPerInstance > 100 {
		errs = append(errs, errors.New("waitlist.max_waits_per_instance must be 1..100"))
	}
	if w.MaxWaits < 1 || w.MaxWaits > 100000 {
		errs = append(errs, errors.New("waitlist.max_waits must be 1..100000"))
	}
	if d := w.LongPollMax.D(); d < time.Second || d > apapp.LongPollMax {
		errs = append(errs, errors.New("waitlist.long_poll_max must be 1s..30s"))
	}
	return errs
}
