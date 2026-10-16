// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package promotions

import (
	"context"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"

	gapp "github.com/katocxl/pantherclaw/internal/grants/app"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
)

// ReasonNotPromoted is the refusal of a new or widened production grant
// for an operation the agent is not promoted for (D9, D39).
const ReasonNotPromoted = "NOT_PROMOTED"

// Gate implements grants' PromotionGate: grants call it on every new or
// widened grant, person- or automation-issued, in the issuing transaction
// (HR-290). Its refusals wrap gapp.ErrNotPromoted.
type Gate struct{}

var _ gapp.PromotionGate = Gate{}

// Check refuses NOT_PROMOTED unless env is not a PRODUCTION environment,
// or ops is an explicit list each of whose entries an ACTIVE promotion of
// the agent in env covers (an equal entry or a covering prefix). nil ops
// (every operation) is never promoted.
func (Gate) Check(ctx context.Context, tx pgx.Tx, org ids.OrgID, agent, env ids.UUID, ops gdomain.Ops) error {
	q := dbq.New(tx)
	kind, err := q.PromotionEnvironmentKind(ctx, org, env)
	if db.IsNoRows(err) {
		return notPromoted("the environment is unknown")
	} else if err != nil {
		return err
	}
	if kind != production {
		return nil
	}
	if ops == nil {
		return notPromoted("a production grant must list its operations; promote the agent for each")
	}
	promoted, err := q.ActivePromotedOperations(ctx, org, agent, env)
	if err != nil {
		return err
	}
	if missing := uncovered(ops, promoted); len(missing) > 0 {
		return notPromoted("the agent is not promoted in this production environment for " + strings.Join(missing, ", "))
	}
	return nil
}

func notPromoted(msg string) error {
	return pcerr.Wrap(gapp.ErrNotPromoted, pcerr.FailedPrecondition, ReasonNotPromoted, clip(msg))
}
