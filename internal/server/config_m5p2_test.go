// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"errors"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/config"
)

func TestM5p2ConfigValidation(t *testing.T) {
	for name, mutate := range map[string]func(*Config){
		"no waits per instance": func(c *Config) { c.Waitlist.MaxWaitsPerInstance = 0 },
		"too many waits":        func(c *Config) { c.Waitlist.MaxWaits = 100001 },
		"a long poll over 30s":  func(c *Config) { c.Waitlist.LongPollMax = config.Duration(31 * time.Second) },
		"no long poll":          func(c *Config) { c.Waitlist.LongPollMax = 0 },
	} {
		c := DefaultConfig()
		mutate(&c)
		if errs := c.validateM5p2(); len(errs) == 0 {
			t.Errorf("%s accepted", name)
		}
	}
	c := DefaultConfig()
	if errs := c.validateM5p2(); len(errs) != 0 {
		t.Fatalf("defaults: %v", errors.Join(errs...))
	}
}
