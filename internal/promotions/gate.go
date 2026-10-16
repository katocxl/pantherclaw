// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package promotions

import (
	"context"
	"slices"
	"strings"
	"time"

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
// (HR-290). Its refusals wrap gapp.ErrNotPromoted. Packages names the
// operations a grant prefix covers (nil: none, so a prefix is refused);
// Pool serves ProvisionalExpiry.
type Gate struct {
	Packages Packages
	Pool     *db.Pool
}

var (
	_ gapp.PromotionGate   = Gate{}
	_ gapp.PromotionExpiry = Gate{}
)

// decision is what the gate decides from.
type decision struct {
	prod  bool
	exact []string
	empty []string
	rows  []dbq.PromotedOperationsRow
}

// read reads, in q's transaction, whether env is a PRODUCTION environment,
// the grant's operations as exact ones, the prefixes nothing is known
// under, and the agent's ACTIVE or unexpired PROVISIONAL promotions there
// (FOR SHARE, D71 G7).
func (g Gate) read(ctx context.Context, q *dbq.Queries, org ids.OrgID, agent, env ids.UUID, ops gdomain.Ops) (decision, error) {
	var d decision
	kind, err := q.PromotionEnvironmentKind(ctx, org, env)
	if db.IsNoRows(err) {
		return decision{prod: true}, notPromoted("the environment is unknown")
	} else if err != nil {
		return d, err
	}
	if d.prod = kind == production; !d.prod || ops == nil {
		return d, nil
	}
	d.exact = []string(ops)
	if slices.ContainsFunc(d.exact, func(op string) bool { _, ok := prefixOf(op); return ok }) {
		c, err := loadCatalog(ctx, q, g.Packages, org)
		if err != nil {
			return d, err
		}
		d.exact, d.empty = c.expand(d.exact)
	}
	d.rows, err = q.PromotedOperations(ctx, org, agent, env)
	return d, err
}

// Check refuses NOT_PROMOTED unless env is not a PRODUCTION environment,
// or ops is an explicit list whose every exact operation has an ACTIVE or
// unexpired PROVISIONAL promotion of the agent in env (D80), and whose
// every prefix such as payments.* has one for each operation currently
// known under it, at least one (D70). nil ops (every operation) is never
// promoted.
func (g Gate) Check(ctx context.Context, tx pgx.Tx, org ids.OrgID, agent, env ids.UUID, ops gdomain.Ops) error {
	d, err := g.read(ctx, dbq.New(tx), org, agent, env, ops)
	switch {
	case err != nil:
		return err
	case !d.prod:
		return nil
	case ops == nil:
		return notPromoted("a production grant must list its operations; promote the agent for each")
	}
	missing := slices.Clone(d.empty)
	for _, op := range d.exact {
		if !slices.ContainsFunc(d.rows, func(r dbq.PromotedOperationsRow) bool { return r.Operation == op }) {
			missing = append(missing, op)
		}
	}
	if len(missing) > 0 {
		return notPromoted("the agent is not promoted in this production environment for " + strings.Join(missing, ", "))
	}
	return nil
}

// ProvisionalExpiry returns the earliest expiry of the PROVISIONAL
// promotions a grant of ops would stand on (nil: none), so grants cap the
// grant's expiry at it: a grant under a provisional promotion ends with it
// (D80).
func (g Gate) ProvisionalExpiry(ctx context.Context, org ids.OrgID, agent, env ids.UUID, ops gdomain.Ops) (*time.Time, error) {
	if g.Pool == nil {
		return nil, nil
	}
	var out *time.Time
	err := g.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		d, err := g.read(ctx, dbq.New(tx), org, agent, env, ops)
		if err != nil {
			return err
		}
		for _, r := range d.rows {
			if r.ExpiresAt != nil && slices.Contains(d.exact, r.Operation) && (out == nil || r.ExpiresAt.Before(*out)) {
				t := *r.ExpiresAt
				out = &t
			}
		}
		return nil
	})
	if pcerr.CodeOf(err) == pcerr.FailedPrecondition {
		return nil, nil // Check refuses it in the issuing transaction
	}
	return out, err
}

func notPromoted(msg string) error {
	return pcerr.Wrap(gapp.ErrNotPromoted, pcerr.FailedPrecondition, ReasonNotPromoted, clip(msg))
}
