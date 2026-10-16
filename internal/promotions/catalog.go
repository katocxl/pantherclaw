// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package promotions

import (
	"context"
	"slices"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Packages reads the org's ACTIVE package versions through the caller's
// queries (definitions/adapters/pgstore.Store.ActivePackagesQ).
type Packages interface {
	ActivePackagesQ(ctx context.Context, q *dbq.Queries, org ids.OrgID) ([]*defs.Package, error)
}

// catalog is what the agent's connections (PromotionAgentConnections) can
// reach now: the operations the active definitions of their packages
// declare and the connections serving each (D70, D93 L2), and the
// consequence operations the consequence rules of every active package
// predict (D71 G10). Without
// Packages it is empty, so no prefix expands and nothing is served (fail
// closed).
type catalog struct {
	ops          []string
	serving      map[string][]ids.UUID
	consequences map[string][]string
}

func loadCatalog(ctx context.Context, q *dbq.Queries, pk Packages, org ids.OrgID, agent ids.UUID) (catalog, error) {
	c := catalog{serving: map[string][]ids.UUID{}, consequences: map[string][]string{}}
	if pk == nil {
		return c, nil
	}
	conns, err := q.PromotionAgentConnections(ctx, org, &agent)
	if err != nil {
		return c, err
	}
	ps, err := pk.ActivePackagesQ(ctx, q, org)
	if err != nil {
		return c, err
	}
	for _, p := range ps {
		var served []ids.UUID
		for _, cn := range conns {
			if cn.Package == p.Name {
				served = append(served, cn.ID)
			}
		}
		// Consequence holds come from every active package, served or not:
		// an agent with no connection yet still needs their approvers.
		for _, r := range p.Consequences {
			if !slices.Contains(c.consequences[r.Operation], r.Consequence.Operation) {
				c.consequences[r.Operation] = append(c.consequences[r.Operation], r.Consequence.Operation)
			}
		}
		if len(served) == 0 {
			continue
		}
		for _, d := range p.Definitions {
			c.ops = append(c.ops, d.Operation)
			for _, id := range served {
				if !slices.Contains(c.serving[d.Operation], id) {
					c.serving[d.Operation] = append(c.serving[d.Operation], id)
				}
			}
		}
	}
	slices.Sort(c.ops)
	c.ops = slices.Compact(c.ops)
	return c, nil
}

// under lists the known operations a prefix such as payments.* matches.
func (c catalog) under(prefix string) []string {
	var out []string
	for _, op := range c.ops {
		if matches(prefix, op) {
			out = append(out, op)
		}
	}
	return out
}

// expand replaces each prefix of ops by the known operations under it,
// sorted and deduplicated; empty lists the prefixes nothing is known under.
func (c catalog) expand(ops []string) (exact, empty []string) {
	for _, op := range ops {
		if _, ok := prefixOf(op); !ok {
			exact = append(exact, op)
			continue
		}
		known := c.under(op)
		if len(known) == 0 {
			empty = append(empty, op)
		}
		exact = append(exact, known...)
	}
	slices.Sort(exact)
	return slices.Compact(exact), empty
}

// KnownUnder lists the operations a prefix such as payments.* covers now
// for the agent: those the active definitions of the packages its
// connections serve declare (D70, D93 L2).
func KnownUnder(ctx context.Context, tx db.TenantTx, pk Packages, agent ids.UUID, prefix string) ([]string, error) {
	c, err := loadCatalog(ctx, dbq.New(tx), pk, tx.OrgID(), agent)
	if err != nil {
		return nil, err
	}
	return c.under(prefix), nil
}
