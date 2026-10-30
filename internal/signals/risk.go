// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package signals

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// RiskLevel is the level of every identity-risk fact the receiver writes.
const RiskLevel = "high"

// riskDeclaration is the built-in provider's one fact (G0 M16 D82).
var riskDeclaration = fdomain.Declaration{
	Name: fdomain.NameIdentityRisk, Type: fdomain.TypeObject, SubjectType: fdomain.SubjectUser, MaxLag: fdomain.MaxLagCeiling,
}

// identityRisk writes pc.identity.risk about the person an accepted event
// names, {event, level: "high", at}, through the built-in provider
// pc.signals, which it creates on first use (G0 M16 D82, founder decision
// F8, HR-441). Policy can only restrict with it. It runs in its own
// savepoint: a failure never loses the event or its case, and is raised
// as an alert and noted on the case (riskNotRecorded). It reports whether
// the fact was written.
func (s *Service) identityRisk(ctx context.Context, tx db.TenantTx, r Received) bool {
	return s.attempt(ctx, tx, r, func(sp pgx.Tx) error {
		q := dbq.New(sp)
		if err := q.EnsureBuiltinFactProvider(ctx, r.Org, ids.NewV7()); err != nil {
			return err
		}
		p, err := q.GetBuiltinFactProvider(ctx, r.Org)
		if err != nil {
			return err
		}
		if err := q.EnsureBuiltinFactDeclaration(ctx, dbq.EnsureBuiltinFactDeclarationParams{
			OrgID: r.Org, ProviderID: p.ID, Name: riskDeclaration.Name, ValueType: string(riskDeclaration.Type),
			SubjectType: riskDeclaration.SubjectType, MaxLagS: int32(riskDeclaration.MaxLag / time.Second), //nolint:gosec // G115: at most a day
		}); err != nil {
			return err
		}
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		v, err := fdomain.EncodeValue(fdomain.Value{Type: fdomain.TypeObject, Object: map[string]any{
			"event": ShortName(r.EventType), "level": RiskLevel, "at": r.IssuedAt.Unix(),
		}})
		if err != nil {
			return err
		}
		source, method := fdomain.BuiltinProvider, "rule"
		_, err = q.PutFact(ctx, dbq.PutFactParams{
			OrgID: r.Org, ID: ids.NewV7(), Name: fdomain.NameIdentityRisk, SubjectType: fdomain.SubjectUser, SubjectID: r.User.String(),
			ProviderID: p.ID, Value: v, ObservedAt: now, Source: &source, Method: &method,
		})
		return err
	})
}

// RiskNotRecordedNote is the case question (or event note) when the
// identity-risk fact could not be written.
const RiskNotRecordedNote = "The identity-risk fact was not recorded: policies using principal.risk do not see this event."

// riskNotRecorded raises an alert that the identity-risk fact of an
// accepted event was not written (D82, HR-441), in the receiver's
// transaction; the case or the event note says so too.
func (s *Service) riskNotRecorded(ctx context.Context, tx db.TenantTx, r Received, evidence []reflexdomain.EvidenceRef, person reflexdomain.Subject) error {
	if s.raiser == nil {
		return nil
	}
	_, err := s.raiser.Raise(ctx, tx.Pgx(), reflexdomain.Signal{
		Org: r.Org, Source: reflexdomain.SourceSystem, Title: "Identity-risk fact not recorded",
		Summary: "An accepted Shared Signals event for person " + r.User.String() + " could not be recorded as pc.identity.risk; " +
			"policies using principal.risk do not see it.",
		Severity: reflexdomain.SeverityHigh, Attention: reflexdomain.AttentionAlert, Basis: reflexdomain.BasisObserved,
		Subjects: []reflexdomain.Subject{person}, Evidence: evidence, GroupKey: "signals.identity_risk",
		DedupeKey: "signals.identity_risk:" + r.Event.String(), OccurredAt: r.IssuedAt,
		Facts: map[string]string{"event": r.Event.String(), "event_type": ShortName(r.EventType)},
	})
	return err
}
