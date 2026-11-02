// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"log/slog"

	"github.com/katocxl/pantherclaw/internal/contentsignals/adapters/outofprocess"
	"github.com/katocxl/pantherclaw/internal/gateway/contentscan"
)

// contentScanner builds the content scan from the operator's configuration
// (G0 M27 D507): the built-in, and the customer-run classifier when one is
// named.
func contentScanner(cfg *Config, log *slog.Logger) (*contentscan.Scanner, error) {
	s := &contentscan.Scanner{Log: log, Timeout: cfg.ContentSignals.ClassifierTimeout.D()}
	if u := cfg.ContentSignals.ClassifierURL; u != "" {
		c, err := outofprocess.New(u)
		if err != nil {
			return nil, err
		}
		s.External = c
	}
	return s, nil
}
