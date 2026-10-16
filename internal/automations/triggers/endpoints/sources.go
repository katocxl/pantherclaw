// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package endpoints

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/automations/triggers/inbound"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	ndomain "github.com/katocxl/pantherclaw/internal/notifications/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
)

// Source bounds (D21).
const (
	DefaultRatePerMinute = 60
	MaxRatePerMinute     = 600
	MaxDescription       = 500
)

var typeName = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,99}$`)

// NewSource describes an event source to create.
type NewSource struct {
	Name          string
	Description   string
	Types         []string
	RatePerMinute int
}

// Source is an inbound event source.
type Source struct {
	ID                  ids.UUID
	Name                string
	Description         string
	Types               []string
	RatePerMinute       int
	State               string
	CreatedBy           ids.UUID
	CreatedAt           time.Time
	ActivatedBy         *ids.UUID
	ActivatedCredential *ids.UUID
	ActivatedAt         *time.Time
	DisabledAt          *time.Time
	// RotationEndsAt is when the previous secret stops verifying.
	RotationEndsAt *time.Time
}

// CreatedSource is a new source; Secret is shown once.
type CreatedSource struct {
	Source Source
	Secret string
}

func sourceOf(r dbq.GetEventSourceRow) Source {
	return Source{
		ID: r.ID, Name: r.Name, Description: r.Description, Types: r.Types, RatePerMinute: int(r.RatePerMinute),
		State: r.State, CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt, ActivatedBy: r.ActivatedBy,
		ActivatedCredential: r.ActivatedCredential, ActivatedAt: r.ActivatedAt, DisabledAt: r.DisabledAt,
		RotationEndsAt: r.PrevUntil,
	}
}

func getSource(ctx context.Context, q *dbq.Queries, org ids.OrgID, id ids.UUID) (Source, error) {
	r, err := q.GetEventSource(ctx, org, id)
	if db.IsNoRows(err) {
		return Source{}, ErrNotFound
	} else if err != nil {
		return Source{}, err
	}
	return sourceOf(r), nil
}

func validSource(in *NewSource) bool {
	if in.RatePerMinute == 0 {
		in.RatePerMinute = DefaultRatePerMinute
	}
	in.Types = slices.Clone(in.Types)
	slices.Sort(in.Types)
	if !ndomain.ValidChannelName(in.Name) || utf8.RuneCountInString(in.Description) > MaxDescription ||
		in.RatePerMinute < 1 || in.RatePerMinute > MaxRatePerMinute ||
		len(in.Types) == 0 || len(in.Types) > inbound.MaxTypes || len(slices.Compact(slices.Clone(in.Types))) != len(in.Types) {
		return false
	}
	for _, t := range in.Types {
		if !typeName.MatchString(t) {
			return false
		}
	}
	return true
}

// CreateEventSource stores a PENDING source and returns its secret once
// (D21). It accepts nothing until a person activates it with a step-up.
func (s *Service) CreateEventSource(ctx context.Context, in NewSource) (CreatedSource, error) {
	c, err := s.manager(ctx, true)
	if err != nil {
		return CreatedSource{}, err
	}
	in.Description = strings.TrimSpace(in.Description)
	if !validSource(&in) {
		return CreatedSource{}, ErrInvalidSource
	}
	secret, err := ndomain.NewSigningSecret()
	if err != nil {
		return CreatedSource{}, err
	}
	id := ids.NewV7()
	var out CreatedSource
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		blob, err := s.envelope.Encrypt(ctx, field(c.Org, sourcesTable, id, secretColumn), SecretPurpose, secret)
		if err != nil {
			return fmt.Errorf("endpoints: encrypt secret: %w", err)
		}
		q := dbq.New(tx)
		err = q.InsertEventSource(ctx, dbq.InsertEventSourceParams{
			OrgID: c.Org, ID: id, Name: in.Name, Description: in.Description, Types: in.Types, Secret: blob,
			RatePerMinute: int32(in.RatePerMinute), CreatedBy: c.Principal.ID, //nolint:gosec // 1..600
		})
		if db.IsUniqueViolation(err) {
			return ErrExists
		} else if err != nil {
			return err
		}
		if err := s.audit(ctx, tx, c, "automation.event_source_created", "automation_event_source", id, map[string]string{
			"name": in.Name, "types": strings.Join(in.Types, ","), "rate_per_minute": fmt.Sprint(in.RatePerMinute),
		}); err != nil {
			return err
		}
		out.Source, err = getSource(ctx, q, c.Org, id)
		return err
	})
	if err != nil {
		return CreatedSource{}, err
	}
	out.Secret = ndomain.FormatSecret(secret)
	return out, nil
}

// ActivateEventSource makes a PENDING source ACTIVE (HR-275): a person
// holding automation.endpoints.manage with a fresh step-up of their own
// key; su is nil over the API, which refuses (D53).
func (s *Service) ActivateEventSource(ctx context.Context, id ids.UUID, su *stepup.StepUp) (Source, error) {
	c, err := s.manager(ctx, true)
	if err != nil {
		return Source{}, err
	}
	if su == nil {
		return Source{}, stepup.ErrStepUp
	}
	var out Source
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		if err := stepup.Check(ctx, tx, c, *su, now); err != nil {
			return err
		}
		src, err := getSource(ctx, q, c.Org, id)
		if err != nil {
			return err
		}
		if src.State != StatePending {
			return ErrState
		}
		n, err := q.ActivateEventSource(ctx, dbq.ActivateEventSourceParams{
			ActivatedBy: &c.Principal.ID, ActivatedCredential: &su.Credential, OrgID: c.Org, ID: id,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrState
		}
		if err := s.audit(ctx, tx, c, "automation.event_source_activated", "automation_event_source", id, map[string]string{
			"name": src.Name, "security_key": su.Credential.String(),
		}); err != nil {
			return err
		}
		out, err = getSource(ctx, q, c.Org, id)
		return err
	})
	return out, err
}

// RotateEventSourceSecret replaces a source's secret with a step-up and
// returns the new one once; the previous one keeps verifying for 24
// hours, and a second rotation waits for that overlap (HR-275).
func (s *Service) RotateEventSourceSecret(ctx context.Context, id ids.UUID, su *stepup.StepUp) (string, error) {
	c, err := s.manager(ctx, true)
	if err != nil {
		return "", err
	}
	if su == nil {
		return "", stepup.ErrStepUp
	}
	secret, err := ndomain.NewSigningSecret()
	if err != nil {
		return "", err
	}
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		if err := stepup.Check(ctx, tx, c, *su, now); err != nil {
			return err
		}
		row, err := q.LoadEventSourceSecrets(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if row.State != StateActive {
			return ErrState
		}
		if row.PrevUntil != nil && row.PrevUntil.After(now) {
			return ErrRotating
		}
		cur, prev, err := s.rotate(ctx, c.Org, sourcesTable, id, row.Secret, secret)
		if err != nil {
			return err
		}
		n, err := q.RotateEventSourceSecret(ctx, dbq.RotateEventSourceSecretParams{Secret: cur, PrevSecret: prev, OrgID: c.Org, ID: id})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrRotating
		}
		return s.audit(ctx, tx, c, "automation.event_source_secret_rotated", "automation_event_source", id,
			map[string]string{"security_key": su.Credential.String()})
	})
	if err != nil {
		return "", err
	}
	return ndomain.FormatSecret(secret), nil
}

// DisableEventSource disables a source for good (no step-up: disabling
// only narrows). Works after the licence lapses.
func (s *Service) DisableEventSource(ctx context.Context, id ids.UUID) (Source, error) {
	c, err := s.manager(ctx, false)
	if err != nil {
		return Source{}, err
	}
	var out Source
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		src, err := getSource(ctx, q, c.Org, id)
		if err != nil {
			return err
		}
		n, err := q.DisableEventSource(ctx, &c.Principal.ID, c.Org, id)
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrState
		}
		if err := s.audit(ctx, tx, c, "automation.event_source_disabled", "automation_event_source", id,
			map[string]string{"from": src.State}); err != nil {
			return err
		}
		out, err = getSource(ctx, q, c.Org, id)
		return err
	})
	return out, err
}

// GetEventSource returns one source (automation.read).
func (s *Service) GetEventSource(ctx context.Context, id ids.UUID) (Source, error) {
	c, err := s.reader(ctx)
	if err != nil {
		return Source{}, err
	}
	var out Source
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = getSource(ctx, dbq.New(tx), c.Org, id)
		return err
	}, db.ReadOnly())
	return out, err
}

// ListEventSources lists the org's sources (automation.read).
func (s *Service) ListEventSources(ctx context.Context) ([]Source, error) {
	c, err := s.reader(ctx)
	if err != nil {
		return nil, err
	}
	var out []Source
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListEventSources(ctx, c.Org)
		if err != nil {
			return err
		}
		out = make([]Source, 0, len(rows))
		for _, r := range rows {
			out = append(out, sourceOf(dbq.GetEventSourceRow(r)))
		}
		return nil
	}, db.ReadOnly())
	return out, err
}
