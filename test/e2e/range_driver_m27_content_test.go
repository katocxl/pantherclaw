// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"context"
	"encoding/json/v2"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
)

// contentMode runs operator.content_mode (G0 M27 D507, D512; RT-158..161):
// the org's mode is written as an applied change would write it, every
// gateway of the org gets a new configuration, and the step returns once the
// stack's gateway runs with it. The Authority reads the mode for itself.
func (d *rangeDriver) contentMode(st domain.Step) (domain.Observation, error) {
	var w struct {
		Mode string `json:"mode"`
	}
	if err := json.Unmarshal(st.With, &w); err != nil {
		return domain.Observation{}, err
	}
	t := d.t
	err := d.s.pool.InTenantTx(context.Background(), d.s.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, `INSERT INTO pc.content_signal_settings (org_id, mode, updated_by) VALUES ($1, $2, 'range')
			ON CONFLICT (org_id) DO UPDATE SET mode = EXCLUDED.mode, updated_by = EXCLUDED.updated_by, updated_at = now()`, d.s.org, w.Mode)
		return err
	})
	if err != nil {
		return domain.Observation{}, err
	}
	gw := d.s.gatewayID(t)
	d.s.db.AdminExec(t, "UPDATE pc.gateways SET config_version = config_version + 1 WHERE org_id = $1", d.s.org)
	d.s.waitConfig(t, d.s.configVersion(t, gw))
	return domain.Observation{}, nil
}
