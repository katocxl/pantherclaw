// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"fmt"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// GatewaysConfig says which gateways PantherClaw hosts (G0 M9 track C,
// decision 7). Only this configuration says so, never a tenant or a
// gateway; connectors are never created on, moved to or delivered to them
// (HR-084).
type GatewaysConfig struct {
	// PantherClawHosted are the ids of the gateways PantherClaw runs.
	PantherClawHosted []string `json:"pantherclaw_hosted" env:"PC_GATEWAYS_PANTHERCLAW_HOSTED"`
}

// pantherClawHosted parses the PantherClaw-hosted gateway ids.
func (c *Config) pantherClawHosted() ([]ids.UUID, error) {
	out := make([]ids.UUID, 0, len(c.Gateways.PantherClawHosted))
	for _, s := range c.Gateways.PantherClawHosted {
		id, err := ids.ParseUUID(s)
		if err != nil {
			return nil, fmt.Errorf("gateways.pantherclaw_hosted: %q is not a gateway id", s)
		}
		out = append(out, id)
	}
	return out, nil
}

func (c *Config) validateGateways() []error {
	if _, err := c.pantherClawHosted(); err != nil {
		return []error{err}
	}
	return nil
}
