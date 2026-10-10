// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"
	"regexp"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	wdomain "github.com/katocxl/pantherclaw/internal/waitlist/domain"
)

// ErrSettingsInvalid refuses a setting outside its bounds.
var ErrSettingsInvalid = pcerr.New(pcerr.InvalidArgument, "WAITLIST_SETTINGS_INVALID",
	"a setting is outside its bounds: deadlines may only be shortened, hold caps only lowered and cooldowns only lengthened")

// Settings are an org's waitlist settings (decisions 6, 7 and 9), in
// seconds and counts. In an update, zero means the default; read back,
// every value is the one in effect.
type Settings struct {
	// BatchCeilings is the batch approval ceiling per currency (canonical
	// decimals); empty turns batch approval off.
	BatchCeilings                                                          map[string]string
	HoldDeadline, ConsumeWindow, AccessRequestDeadline, ToolReviewDeadline int32
	RestorationDeadline, ReconciliationDeadline                            int32
	MaxHoldsPerGrant, MaxHoldsPerRun                                       int32
	MinAccountAge, MinRoleAge, MinCredentialAge, SelfGrantDelay            int32
	UpdatedBy                                                              string
	UpdatedAt                                                              time.Time
}

// bound is a setting's range and default.
type bound struct{ min, max, def int32 }

func secs(d time.Duration) int32 { return int32(d / time.Second) } //nolint:gosec // defaults, at most 30 days

var (
	cd     = apdomain.DefaultCooldowns()
	bounds = map[string]bound{
		"hold_deadline":           {300, 3600, secs(apdomain.DefaultDeadline)},
		"consume_window":          {60, 900, secs(apdomain.DefaultConsumeWindow)},
		"access_request_deadline": {3600, 604800, secs(wdomain.DefaultDeadlines[wdomain.KindAccessRequest])},
		"tool_review_deadline":    {3600, 2592000, secs(wdomain.DefaultDeadlines[wdomain.KindToolReview])},
		"restoration_deadline":    {300, 86400, secs(wdomain.DefaultDeadlines[wdomain.KindRestoration])},
		"reconciliation_deadline": {3600, 259200, secs(wdomain.DefaultDeadlines[wdomain.KindReconciliation])},
		"max_holds_per_grant":     {1, 100, 20},
		"max_holds_per_run":       {1, 5, 5},
		"min_account_age":         {604800, 31536000, secs(cd.AccountAge)},
		"min_role_age":            {86400, 31536000, secs(cd.RoleAge)},
		"min_credential_age":      {86400, 31536000, secs(cd.CredentialAge)},
		"self_grant_delay":        {86400, 31536000, secs(cd.SelfGrantDelay)},
	}
	currency = regexp.MustCompile(`^[A-Z]{3}$`)
	decimal  = regexp.MustCompile(`^(0|[1-9][0-9]{0,17})(\.[0-9]{1,8})?$`)
)

func (s *Settings) fields() map[string]*int32 {
	return map[string]*int32{
		"hold_deadline": &s.HoldDeadline, "consume_window": &s.ConsumeWindow, "access_request_deadline": &s.AccessRequestDeadline,
		"tool_review_deadline": &s.ToolReviewDeadline, "restoration_deadline": &s.RestorationDeadline,
		"reconciliation_deadline": &s.ReconciliationDeadline, "max_holds_per_grant": &s.MaxHoldsPerGrant,
		"max_holds_per_run": &s.MaxHoldsPerRun, "min_account_age": &s.MinAccountAge, "min_role_age": &s.MinRoleAge,
		"min_credential_age": &s.MinCredentialAge, "self_grant_delay": &s.SelfGrantDelay,
	}
}

func set(v int32) *int32 {
	if v == 0 {
		return nil
	}
	return &v
}

func orZero(p *int32) int32 {
	if p == nil {
		return 0
	}
	return *p
}

// GetSettings returns the org's settings in effect. It needs
// waitlist.manage at org scope.
func (rd *Reader) GetSettings(ctx context.Context) (Settings, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Settings{}, err
	}
	if err := c.Require(td.PermWaitlistManage, td.OrgPath(c.Org)); err != nil {
		return Settings{}, err
	}
	var out Settings
	err = rd.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		row, err := dbq.New(tx).GetWaitlistSettings(ctx, c.Org)
		if err != nil && !db.IsNoRows(err) {
			return err
		}
		out = settingsOf(row)
		return nil
	}, db.ReadOnly())
	return out, err
}

func settingsOf(r dbq.PcWaitlistSetting) Settings {
	s := Settings{
		BatchCeilings: map[string]string{}, HoldDeadline: orZero(r.HoldDeadlineS), ConsumeWindow: orZero(r.ConsumeWindowS),
		AccessRequestDeadline: orZero(r.AccessRequestDeadlineS), ToolReviewDeadline: orZero(r.ToolReviewDeadlineS),
		RestorationDeadline: orZero(r.RestorationDeadlineS), ReconciliationDeadline: orZero(r.ReconciliationDeadlineS),
		MinAccountAge: orZero(r.MinAccountAgeS), MinRoleAge: orZero(r.MinRoleAgeS), MinCredentialAge: orZero(r.MinCredentialAgeS),
		SelfGrantDelay: orZero(r.SelfGrantDelayS), UpdatedBy: r.UpdatedBy, UpdatedAt: r.UpdatedAt,
	}
	if r.MaxHoldsPerGrant.Valid {
		s.MaxHoldsPerGrant = int32(r.MaxHoldsPerGrant.Int16)
	}
	if r.MaxHoldsPerRun.Valid {
		s.MaxHoldsPerRun = int32(r.MaxHoldsPerRun.Int16)
	}
	if len(r.BatchCeilings) > 0 {
		_ = json.Unmarshal(r.BatchCeilings, &s.BatchCeilings)
	}
	for k, p := range s.fields() {
		if *p == 0 {
			*p = bounds[k].def
		}
	}
	return s
}

// UpdateSettings replaces the org's settings (zero: the default) and
// returns those in effect. Each value must lie within its bounds:
// deadlines no longer than the defaults, hold caps no higher and cooldowns
// no shorter (decisions 6, 7 and 9). It needs waitlist.manage at org scope
// and is audited.
func (w *Writer) UpdateSettings(ctx context.Context, s Settings) (Settings, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Settings{}, err
	}
	if err := c.Require(td.PermWaitlistManage, td.OrgPath(c.Org)); err != nil {
		return Settings{}, err
	}
	changed := []string{}
	for k, p := range s.fields() {
		b := bounds[k]
		if *p != 0 && (*p < b.min || *p > b.max) {
			return Settings{}, ErrSettingsInvalid
		}
		if *p != 0 {
			changed = append(changed, k)
		}
	}
	if len(s.BatchCeilings) > 16 {
		return Settings{}, ErrSettingsInvalid
	}
	for cur, v := range s.BatchCeilings {
		if !currency.MatchString(cur) || !decimal.MatchString(v) {
			return Settings{}, ErrSettingsInvalid
		}
	}
	if s.BatchCeilings == nil {
		s.BatchCeilings = map[string]string{}
	}
	ceilings, err := json.Marshal(s.BatchCeilings, json.Deterministic(true))
	if err != nil {
		return Settings{}, err
	}
	p := dbq.UpsertWaitlistSettingsParams{
		OrgID: c.Org, BatchCeilings: ceilings, HoldDeadlineS: set(s.HoldDeadline), ConsumeWindowS: set(s.ConsumeWindow),
		AccessRequestDeadlineS: set(s.AccessRequestDeadline), ToolReviewDeadlineS: set(s.ToolReviewDeadline),
		RestorationDeadlineS: set(s.RestorationDeadline), ReconciliationDeadlineS: set(s.ReconciliationDeadline),
		MinAccountAgeS: set(s.MinAccountAge), MinRoleAgeS: set(s.MinRoleAge), MinCredentialAgeS: set(s.MinCredentialAge),
		SelfGrantDelayS: set(s.SelfGrantDelay), UpdatedBy: c.Principal.String(),
	}
	if s.MaxHoldsPerGrant != 0 {
		p.MaxHoldsPerGrant = pgtype.Int2{Int16: int16(s.MaxHoldsPerGrant), Valid: true} //nolint:gosec // ≤ 100
	}
	if s.MaxHoldsPerRun != 0 {
		p.MaxHoldsPerRun = pgtype.Int2{Int16: int16(s.MaxHoldsPerRun), Valid: true} //nolint:gosec // ≤ 5
	}
	var out Settings
	err = w.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := q.UpsertWaitlistSettings(ctx, p); err != nil {
			return err
		}
		if _, err := audit.Record(ctx, tx, audit.Event{
			Name: "waitlist.settings_updated", Actor: c.Actor(), Outcome: audit.Success,
			Object:  &audit.Object{Type: "org", ID: c.Org.String()},
			Details: map[string]string{"set": strconv.Itoa(len(changed)), "batch_currencies": strconv.Itoa(len(s.BatchCeilings))},
		}); err != nil {
			return err
		}
		row, err := q.GetWaitlistSettings(ctx, c.Org)
		out = settingsOf(row)
		return err
	})
	return out, err
}
