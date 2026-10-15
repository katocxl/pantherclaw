// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/katocxl/pantherclaw/internal/cases/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	reflexports "github.com/katocxl/pantherclaw/internal/reflex/ports"
)

// Opener implements reflexports.CaseOpener (D1, D55): other parts of the
// product (detections, response, Shared Signals) open a case in their own
// transaction. It checks no caller permission (its callers are the
// product, not a person) but needs the Team edition: below it, Open
// returns EDITION_REQUIRED and opens nothing.
type Opener struct {
	Editions Editions
}

var _ reflexports.CaseOpener = (*Opener)(nil)

// Open opens a case from seed in tx: a LINK entry per subject, evidence
// ref, alert and incident, and an open QUESTION per question, all written
// by seed.Opener. It never adds a FACT: facts are an investigator's.
func (o *Opener) Open(ctx context.Context, tx pgx.Tx, s reflexdomain.CaseSeed) (ids.UUID, error) {
	if err := cases(ctx, o.Editions); err != nil {
		return ids.UUID{}, err
	}
	if s.Opener.Type == "" || len(s.Opener.Type) > 32 || s.Opener.ID == "" || len(s.Opener.ID) > 256 ||
		len(s.Evidence) > reflexdomain.MaxEvidence {
		return ids.UUID{}, ErrBadSubject
	}
	if err := checkSeed(s.Subjects, s.Questions); err != nil {
		return ids.UUID{}, err
	}
	for _, e := range s.Evidence {
		if !e.Valid() {
			return ids.UUID{}, ErrBadSubject
		}
	}
	ttx, err := db.AdoptTenantTx(ctx, tx, s.Org)
	if err != nil {
		return ids.UUID{}, err
	}
	k, err := seed(ctx, ttx, seedOf{
		title: s.Title, source: s.Source, opener: domain.Author{Type: string(s.Opener.Type), ID: s.Opener.ID},
		subjects: s.Subjects, evidence: s.Evidence, questions: s.Questions, alert: s.AlertID, incident: s.IncidentID,
	})
	if err != nil {
		return ids.UUID{}, err
	}
	return k.ID, nil
}

// NewOpener returns the CaseOpener other streams open cases with (D1, D49).
func NewOpener(e Editions) *Opener { return &Opener{Editions: e} }
