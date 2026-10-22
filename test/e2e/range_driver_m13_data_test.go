// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"context"
	"fmt"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
)

// deleteOrg runs operator.delete_org (G0 M13 D22, D34; RT-068): the org
// becomes DELETED, as the data.delete_org job's first step makes it, and
// the step returns once the gateway's own view of its containment stream
// has gone stale (the server stopped confirming a DELETED org's state).
func (d *rangeDriver) deleteOrg() (domain.Observation, error) {
	err := d.s.pool.InTenantTx(context.Background(), d.s.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, "UPDATE pc.orgs SET state = 'DELETED', updated_at = now() WHERE id = $1", d.s.org)
		return err
	})
	if err != nil {
		return domain.Observation{}, err
	}
	deadline := time.Now().Add(10 * time.Second)
	for d.s.gw.Contained() == nil {
		if time.Now().After(deadline) {
			return domain.Observation{}, fmt.Errorf("the gateway still dispatches 10 s after its org was deleted")
		}
		time.Sleep(20 * time.Millisecond)
	}
	return domain.Observation{}, nil
}
