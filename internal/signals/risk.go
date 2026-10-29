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
// savepoint: a failure is logged and never loses the event or its case.
func (s *Service) identityRisk(ctx context.Context, tx db.TenantTx, r Received) {
	s.attempt(ctx, tx, r, func(sp pgx.Tx) error {
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
			SubjectType: riskDeclaration.SubjectType, MaxLagS: int32(riskDeclaration.MaxLag / time.Second),
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
