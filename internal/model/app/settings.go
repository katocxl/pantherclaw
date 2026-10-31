// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app is an organization's optional model drafting (G0 M21 D304,
// D309; G16, F181, F304, TB13): its settings and write-only key, the off
// switches, the caps, and the one audited path to a provider.
//
// Drafting needs all of: the server's PC_MODEL_DRAFTING_ENABLED (the
// self-hosted gate and the platform kill switch), the Business edition, and
// the organization's own switch, which is off until a person turns it on
// (HR-541). Turning it on or setting the key changes where data may go, so
// it takes a person, a fresh step-up, and a notice to every org admin;
// turning it off or clearing the key takes neither, so nothing slows a
// person down on the way out.
package app

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgtype"

	billingdomain "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/model/adapters/anthropic"
	"github.com/katocxl/pantherclaw/internal/model/ports"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

const (
	// SecretPurpose is the DEK purpose of model provider keys.
	SecretPurpose = "model_secrets"
	settingsTable = "model_settings"
	keyColumn     = "key_ciphertext"
	// maxKey bounds a provider key, in bytes.
	maxKey = 512
	// noticeType is the notice to org admins (D309).
	noticeType = "security.model_drafting_changed"
)

// Errors.
var (
	ErrEdition = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED",
		"model drafting needs the Business edition")
	ErrPlatformOff = pcerr.New(pcerr.FailedPrecondition, "MODEL_DRAFTING_UNAVAILABLE",
		"model drafting is not enabled on this server")
	ErrOff = pcerr.New(pcerr.FailedPrecondition, "MODEL_DRAFTING_OFF",
		"model drafting is off for this organization")
	ErrNoKey = pcerr.New(pcerr.FailedPrecondition, "MODEL_KEY_NOT_SET",
		"set the organization's model provider key first")
	ErrHuman = pcerr.New(pcerr.PermissionDenied, "HUMAN_REQUIRED",
		"only a person can change model drafting")
	ErrInvalidKey = pcerr.New(pcerr.InvalidArgument, "MODEL_KEY_INVALID",
		"the model provider key is not valid")
	ErrInvalidModel = pcerr.New(pcerr.InvalidArgument, "MODEL_ID_INVALID",
		"the model id is not valid")
	ErrCapTooHigh = pcerr.New(pcerr.InvalidArgument, "MODEL_CAP_TOO_HIGH",
		"an organization can only lower the server's caps")
	ErrRateCap = pcerr.New(pcerr.ResourceExhausted, "MODEL_RATE_CAP",
		"the organization's model calls a minute are used up; try again shortly")
	ErrBudgetCap = pcerr.New(pcerr.ResourceExhausted, "MODEL_BUDGET_CAP",
		"the organization's model budget for today is used up")
	ErrEnvironmentCondition = pcerr.New(pcerr.InvalidArgument, "MODEL_ENVIRONMENT_UNSUPPORTED",
		"a draft cannot hold an environment condition: draft without it, and add the environment in the editor")
	ErrDraftNotFound = pcerr.New(pcerr.NotFound, "MODEL_DRAFT_NOT_FOUND",
		"that version was not drafted by a model")
)

// Editions reports the deployment's edition (billing.Service).
type Editions interface {
	Current(ctx context.Context) (billingdomain.Entitlements, error)
}

// Notifier enqueues the notice to org admins in the change's transaction.
type Notifier interface {
	Enqueue(ctx context.Context, tx db.TenantTx, m napp.Message) (napp.Enqueued, error)
}

// Config is the server's part (D309). The caps are both the default and the
// maximum: an organization can only lower them.
type Config struct {
	// Enabled is PC_MODEL_DRAFTING_ENABLED.
	Enabled        bool
	CallsPerMinute int
	TokensPerDay   int64
}

// Service implements model drafting's settings and calls.
type Service struct {
	Pool     *db.Pool
	Envelope *pccrypto.Envelope
	Editions Editions
	Notify   Notifier
	Provider ports.Provider
	// Policies, Operations and Params serve policy drafts.
	Policies   PolicyDrafts
	Operations Operations
	Params     []Param
	// Automations serves automation drafts; a guard may name only the Builtin
	// operations, the packages PantherClaw ships.
	Automations AutomationDrafts
	Builtin     []string
	Clock       clock.Clock
	Config      Config
}

func (s *Service) now() time.Time {
	if s.Clock == nil {
		return time.Now()
	}
	return s.Clock.Now()
}

// callerWith is the caller, holding p at the organization.
func callerWith(ctx context.Context, p td.Permission) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	return c, c.Require(p, td.OrgPath(c.Org))
}

// Settings is an organization's settings, without its key.
type Settings struct {
	Enabled        bool
	Available      bool
	KeySet         bool
	KeySetAt       *time.Time
	Model          string
	CallsPerMinute int
	TokensPerDay   int64
}

func (s *Service) field(org ids.OrgID) pccrypto.FieldContext {
	return pccrypto.FieldContext{Org: org, Table: settingsTable, Column: keyColumn, RowID: org.String()}
}

// entitled refuses without the server's switch and the Business edition.
func (s *Service) entitled(ctx context.Context) error {
	if !s.Config.Enabled {
		return ErrPlatformOff
	}
	if s.Editions == nil {
		return ErrEdition
	}
	e, err := s.Editions.Current(ctx)
	if err != nil {
		return err
	}
	if !e.ModelDrafting() {
		return ErrEdition
	}
	return nil
}

// person is the caller of every change: a person holding org.update.
func person(ctx context.Context) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	if err := c.Require(td.PermOrgUpdate, td.OrgPath(c.Org)); err != nil {
		return c, err
	}
	if !c.Human() {
		return c, ErrHuman
	}
	return c, nil
}

func (s *Service) view(ctx context.Context, q *dbq.Queries, org ids.OrgID) (Settings, error) {
	out := Settings{
		Available: s.entitled(ctx) == nil, Model: anthropic.DefaultModel,
		CallsPerMinute: s.Config.CallsPerMinute, TokensPerDay: s.Config.TokensPerDay,
	}
	row, err := q.GetModelSettings(ctx, org)
	if db.IsNoRows(err) {
		return out, nil
	}
	if err != nil {
		return Settings{}, err
	}
	out.Enabled, out.Model, out.KeySet = row.Enabled, row.Model, len(row.KeyCiphertext) > 0
	out.KeySetAt = row.KeySetAt
	out.CallsPerMinute, out.TokensPerDay = s.caps(row)
	return out, nil
}

// caps are the limits in force: the organization's when it lowered them.
func (s *Service) caps(row dbq.PcModelSetting) (int, int64) {
	calls, tokens := s.Config.CallsPerMinute, s.Config.TokensPerDay
	if row.CallsPerMinute != nil && int(*row.CallsPerMinute) < calls {
		calls = int(*row.CallsPerMinute)
	}
	if row.TokensPerDay.Valid && row.TokensPerDay.Int64 < tokens {
		tokens = row.TokensPerDay.Int64
	}
	return calls, tokens
}

// Get returns the organization's settings, never its key.
func (s *Service) Get(ctx context.Context) (Settings, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Settings{}, err
	}
	if err := c.Require(td.PermOrgRead, td.OrgPath(c.Org)); err != nil {
		return Settings{}, err
	}
	var out Settings
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = s.view(ctx, dbq.New(tx), c.Org)
		return err
	}, db.ReadOnly())
	return out, err
}

// change runs f in c's transaction and returns the settings after it.
func (s *Service) change(ctx context.Context, c tenancy.Caller, f func(ctx context.Context, tx db.TenantTx, q *dbq.Queries) error) (Settings, error) {
	var out Settings
	err := s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := q.EnsureModelSettings(ctx, c.Org); err != nil {
			return err
		}
		if err := f(ctx, tx, q); err != nil {
			return err
		}
		var err error
		out, err = s.view(ctx, q, c.Org)
		return err
	})
	return out, err
}

func (s *Service) record(ctx context.Context, tx db.TenantTx, c tenancy.Caller, name string, details map[string]string) error {
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: c.Actor(), Outcome: audit.Success,
		Object: &audit.Object{Type: "model_settings", ID: c.Org.String()}, Details: details,
	})
	return err
}

// stepped checks the fresh step-up of a change that widens where data may
// go, by the database clock.
func stepped(ctx context.Context, tx db.TenantTx, q *dbq.Queries, c tenancy.Caller, su stepup.StepUp) error {
	now, err := q.DBNow(ctx)
	if err != nil {
		return err
	}
	return stepup.Check(ctx, tx, c, su, now)
}

// notifyAdmins tells every org admin, in the change's transaction, so a
// rolled-back change tells nobody.
func (s *Service) notifyAdmins(ctx context.Context, tx db.TenantTx, q *dbq.Queries, c tenancy.Caller, change string) error {
	if s.Notify == nil {
		return errors.New("model: no notifier: a change that needs a notice cannot be made")
	}
	admins, err := q.ActiveUsersWithOrgRole(ctx, c.Org, string(td.RoleOrgAdmin))
	if err != nil {
		return err
	}
	_, err = s.Notify.Enqueue(ctx, tx, napp.Message{
		Org: c.Org, Type: noticeType, Personal: admins,
		Params: map[string]string{"change": change, "user": c.Principal.ID.String()},
	})
	return err
}

// Enable turns drafting on (D309): a person, a fresh step-up, a stored key,
// and a notice to every org admin.
func (s *Service) Enable(ctx context.Context, su stepup.StepUp) (Settings, error) {
	c, err := person(ctx)
	if err != nil {
		return Settings{}, err
	}
	if err := s.entitled(ctx); err != nil {
		return Settings{}, err
	}
	return s.change(ctx, c, func(ctx context.Context, tx db.TenantTx, q *dbq.Queries) error {
		if err := stepped(ctx, tx, q, c, su); err != nil {
			return err
		}
		n, err := q.EnableModelDrafting(ctx, &c.Principal.ID, &su.Credential, c.Org)
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrNoKey
		}
		if err := s.record(ctx, tx, c, "model.drafting_enabled", map[string]string{"security_key": su.Credential.String()}); err != nil {
			return err
		}
		return s.notifyAdmins(ctx, tx, q, c, "ENABLED")
	})
}

// SetKey stores the organization's key (D309): a person, a fresh step-up,
// and a notice to every org admin. The key is never returned or logged.
func (s *Service) SetKey(ctx context.Context, key string, su stepup.StepUp) (Settings, error) {
	c, err := person(ctx)
	if err != nil {
		return Settings{}, err
	}
	if err := s.entitled(ctx); err != nil {
		return Settings{}, err
	}
	if !validKey(key) {
		return Settings{}, ErrInvalidKey
	}
	return s.change(ctx, c, func(ctx context.Context, tx db.TenantTx, q *dbq.Queries) error {
		if err := stepped(ctx, tx, q, c, su); err != nil {
			return err
		}
		blob, err := s.Envelope.Encrypt(ctx, s.field(c.Org), SecretPurpose, []byte(key))
		if err != nil {
			return fmt.Errorf("model: encrypt key: %w", err)
		}
		if err := q.SetModelKey(ctx, blob, &c.Principal.ID, c.Org); err != nil {
			return err
		}
		if err := s.record(ctx, tx, c, "model.key_set", map[string]string{"security_key": su.Credential.String()}); err != nil {
			return err
		}
		return s.notifyAdmins(ctx, tx, q, c, "KEY_SET")
	})
}

func validKey(key string) bool {
	if key == "" || len(key) > maxKey || !utf8.ValidString(key) {
		return false
	}
	for _, r := range key {
		if r <= ' ' || r == 0x7f {
			return false
		}
	}
	return true
}

// Disable turns drafting off. It needs no step-up and no edition: an
// organization can always leave.
func (s *Service) Disable(ctx context.Context) (Settings, error) {
	c, err := person(ctx)
	if err != nil {
		return Settings{}, err
	}
	return s.change(ctx, c, func(ctx context.Context, tx db.TenantTx, q *dbq.Queries) error {
		n, err := q.DisableModelDrafting(ctx, c.Org)
		if err != nil || n == 0 {
			return err
		}
		return s.record(ctx, tx, c, "model.drafting_disabled", nil)
	})
}

// ClearKey removes the key and turns drafting off, without a step-up.
func (s *Service) ClearKey(ctx context.Context) (Settings, error) {
	c, err := person(ctx)
	if err != nil {
		return Settings{}, err
	}
	return s.change(ctx, c, func(ctx context.Context, tx db.TenantTx, q *dbq.Queries) error {
		n, err := q.ClearModelKey(ctx, c.Org)
		if err != nil || n == 0 {
			return err
		}
		return s.record(ctx, tx, c, "model.key_cleared", nil)
	})
}

// Limits is what an organization may set without a step-up. Zero caps mean
// the server's.
type Limits struct {
	Model          string
	CallsPerMinute int
	TokensPerDay   int64
}

// checkLimits refuses a model id that cannot be one, and any cap above the
// server's.
func (s *Service) checkLimits(l Limits) error {
	if !anthropic.ValidModel(l.Model) {
		return ErrInvalidModel
	}
	if l.CallsPerMinute < 0 || l.TokensPerDay < 0 || l.CallsPerMinute > s.Config.CallsPerMinute || l.TokensPerDay > s.Config.TokensPerDay {
		return ErrCapTooHigh
	}
	return nil
}

// SetLimits sets the model id and lowers the caps.
func (s *Service) SetLimits(ctx context.Context, l Limits) (Settings, error) {
	c, err := person(ctx)
	if err != nil {
		return Settings{}, err
	}
	if err := s.checkLimits(l); err != nil {
		return Settings{}, err
	}
	var calls *int32
	var tokens pgtype.Int8
	if l.CallsPerMinute > 0 {
		v := int32(l.CallsPerMinute) //nolint:gosec // at most the server's cap, checked above
		calls = &v
	}
	if l.TokensPerDay > 0 {
		tokens = pgtype.Int8{Int64: l.TokensPerDay, Valid: true}
	}
	return s.change(ctx, c, func(ctx context.Context, tx db.TenantTx, q *dbq.Queries) error {
		if err := q.SetModelLimits(ctx, dbq.SetModelLimitsParams{Model: l.Model, CallsPerMinute: calls, TokensPerDay: tokens, OrgID: c.Org}); err != nil {
			return err
		}
		return s.record(ctx, tx, c, "model.settings_updated", map[string]string{
			"model": l.Model, "calls_per_minute": strconv.Itoa(l.CallsPerMinute), "usage_per_day": strconv.FormatInt(l.TokensPerDay, 10),
		})
	})
}
