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

// catalog is what the org's ACTIVE connections can reach now: the
// operations the active definitions of their packages declare, and the
// consequence operations each one's consequence rules predict (D70, D71
// G10). Without Packages it is empty, so no prefix expands (fail closed).
type catalog struct {
	ops          []string
	consequences map[string][]string
}

func loadCatalog(ctx context.Context, q *dbq.Queries, pk Packages, org ids.OrgID) (catalog, error) {
	c := catalog{consequences: map[string][]string{}}
	if pk == nil {
		return c, nil
	}
	served, err := q.PromotionConnectionPackages(ctx, org)
	if err != nil {
		return c, err
	}
	ps, err := pk.ActivePackagesQ(ctx, q, org)
	if err != nil {
		return c, err
	}
	for _, p := range ps {
		if !slices.Contains(served, p.Name) {
			continue
		}
		for _, d := range p.Definitions {
			c.ops = append(c.ops, d.Operation)
		}
		for _, r := range p.Consequences {
			if !slices.Contains(c.consequences[r.Operation], r.Consequence.Operation) {
				c.consequences[r.Operation] = append(c.consequences[r.Operation], r.Consequence.Operation)
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

// KnownUnder lists the operations a prefix such as payments.* covers now:
// those the active definitions of the packages the org's ACTIVE
// connections serve declare (D70).
func KnownUnder(ctx context.Context, tx db.TenantTx, pk Packages, prefix string) ([]string, error) {
	c, err := loadCatalog(ctx, dbq.New(tx), pk, tx.OrgID())
	if err != nil {
		return nil, err
	}
	return c.under(prefix), nil
}
