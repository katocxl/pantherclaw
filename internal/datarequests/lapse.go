// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package datarequests

import (
	"context"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"strconv"
	"time"
)

// Daily refreshes time-driven lapses, catches up each due reminder exactly
// once, creates day-90 deletion requests, and removes expired export bytes.
func (s *Service) Daily(ctx context.Context, org ids.OrgID) error {
	return s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := q.LockOrgAdmins(ctx, org); err != nil {
			return err
		}
		state, err := q.OrgState(ctx, org)
		if err != nil {
			return err
		}
		if state == "DELETED" {
			return nil
		}
		expired, err := q.ExpiredExports(ctx, org)
		if err != nil {
			return err
		}
		for _, id := range expired {
			if _, err := q.DeleteDataRequestParts(ctx, org, id); err != nil {
				return err
			}
			if _, err := q.ExpireExport(ctx, org, id); err != nil {
				return err
			}
		}
		if !s.LapseEnabled || state != "ACTIVE" {
			return nil
		}
		lapse, err := q.RefreshPlanLapse(ctx, org)
		if db.IsNoRows(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if lapse == nil {
			return nil
		}
		now, err := q.TenantDatabaseTime(ctx)
		if err != nil {
			return err
		}
		admins, err := deletionAdmins(ctx, q, org)
		if err != nil {
			return err
		}
		day := int(now.Sub(*lapse) / (24 * time.Hour))
		for _, milestone := range []int{0, 30, 60, 83} {
			if day < milestone {
				continue
			}
			if s.Notify == nil {
				continue
			}
			_, err := s.Notify.Enqueue(ctx, tx, napp.Message{Org: org, Type: "billing.lapse_reminder", Params: map[string]string{"days_left": strconv.Itoa(max(0, 90-day))}, Personal: admins, PersonalOnly: true, DedupeKey: "lapse:" + lapse.UTC().Format(time.RFC3339Nano) + ":" + strconv.Itoa(milestone)})
			if err != nil {
				return err
			}
		}
		if day < 90 {
			return nil
		}
		_, err = q.OpenDeletionRequest(ctx, org)
		if err == nil {
			return nil
		}
		if !db.IsNoRows(err) {
			return err
		}
		accts, err := q.AccountsOfUsers(ctx, org, admins)
		if err != nil {
			return err
		}
		id, reason := ids.NewV7(), "lapse_90d"
		if err := q.InsertDataRequest(ctx, dbq.InsertDataRequestParams{OrgID: org, ID: id, Kind: "DELETION", State: "PENDING", Reason: &reason, WindowEnd: &now, LapsedAt: lapse, AdminAccounts: accts}); err != nil {
			return err
		}
		return enqueue(ctx, s.Jobs, tx, org, id, true, now)
	})
}
