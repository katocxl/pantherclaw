// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Connection health (G0 M8 track C, F358): what a person needs to judge a
// connection at a glance, from records PantherClaw already keeps.

// Health windows.
const (
	// DeliveryWindow is how far back delivery failures are counted.
	DeliveryWindow = 24 * time.Hour
	// DependentWindow is how far back an agent that used the connection
	// counts as depending on it.
	DependentWindow = 30 * 24 * time.Hour
	// MaxDependents bounds the agents listed.
	MaxDependents = 50
)

// Circuit is one gateway's circuit for a connection (HR-078).
type Circuit struct {
	Gateway        ids.UUID
	Open           bool
	Unknown, Total int32
	OpenedAt       *time.Time
	ReportedAt     time.Time
}

// Deliveries are the outcomes recorded for a connection's actions since a
// time; a zero time is none. Delegated counts the actions an agent ran
// itself, whose result PantherClaw never learns: they are neither failures
// nor successes (HR-024).
type Deliveries struct {
	Since                    time.Time
	Failed, Unknown          int32
	LastFailure, LastSuccess time.Time
	Delegated                int32
	LastDelegated            time.Time
}

// DependentAgent is an agent whose runs used a connection.
type DependentAgent struct {
	Agent    ids.UUID
	Name     string
	LastUsed time.Time
}

// Health is a connection's health.
type Health struct {
	Connection Connection
	Circuits   []Circuit
	// Permissions are what PantherClaw's credential for it is used for.
	Permissions              []Permission
	LastTest, LastPassedTest *TestResult
	Deliveries               Deliveries
	// Agents used it; AgentsHidden: the caller may not read agents
	// org-wide, so none are listed.
	Agents []DependentAgent
	// GrantedAgents hold an active grant that allows an operation the
	// connection serves; LastUsed is unset.
	GrantedAgents []DependentAgent
	AgentsHidden  bool
}

// Health returns a connection's health (connection.read; the dependent
// agents also need agent.read).
func (s *Service) Health(ctx context.Context, id ids.UUID) (Health, error) {
	c, err := s.caller(ctx, td.PermConnectionRead)
	if err != nil {
		return Health{}, err
	}
	seesAgents := false
	if cl, err := tenancy.CallerFrom(ctx); err == nil && cl.Require(td.PermAgentRead, td.OrgPath(cl.Org)) == nil {
		seesAgents = true
	}
	out := Health{AgentsHidden: !seesAgents}
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		conn, err := q.GetConnection(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if out.Connection, err = load(ctx, q, conn); err != nil {
			return err
		}
		circuits, err := q.ListConnectionCircuits(ctx, c.Org, id)
		if err != nil {
			return err
		}
		for _, r := range circuits {
			out.Circuits = append(out.Circuits, Circuit{
				Gateway: r.GatewayID, Open: r.State == "OPEN", Unknown: r.UnknownCount, Total: r.TotalCount, OpenedAt: r.OpenedAt,
				ReportedAt: r.ReportedAt,
			})
		}
		if pin, err := q.PinnedPackageRaw(ctx, c.Org, conn.Package); err == nil {
			if p, err := manifest.Decode(pin.Raw); err == nil {
				out.Permissions = Declare(out.Connection, p).Permissions
			}
		} else if !db.IsNoRows(err) {
			return err
		}
		if out.LastTest, err = latest(ctx, q, c.Org, id, false); err != nil {
			return err
		}
		if out.LastPassedTest, err = latest(ctx, q, c.Org, id, true); err != nil {
			return err
		}
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		out.Deliveries.Since = now.Add(-DeliveryWindow)
		d, err := q.ConnectionDeliveries(ctx, c.Org, &id, out.Deliveries.Since)
		if err != nil {
			return err
		}
		out.Deliveries.Failed, out.Deliveries.Unknown = d.Failed, d.Unknown
		out.Deliveries.LastFailure, out.Deliveries.LastSuccess = unlessEpoch(d.LastFailureAt), unlessEpoch(d.LastSuccessAt)
		out.Deliveries.Delegated, out.Deliveries.LastDelegated = d.Delegated, unlessEpoch(d.LastDelegatedAt)
		if !seesAgents {
			return nil
		}
		agents, err := q.ConnectionDependentAgents(ctx, dbq.ConnectionDependentAgentsParams{
			OrgID: c.Org, ConnectionID: &id, Since: now.Add(-DependentWindow), MaxRows: MaxDependents,
		})
		for _, a := range agents {
			out.Agents = append(out.Agents, DependentAgent{Agent: a.AgentID, Name: a.Name, LastUsed: a.LastUsedAt})
		}
		if err != nil {
			return err
		}
		out.GrantedAgents, err = grantedAgents(ctx, q, c.Org, conn)
		return err
	})
	return out, err
}

// grantedAgents are the agents holding an active, unexpired grant whose
// bounds allow an operation the connection serves (a grant that does not
// bound operations allows them all), by name, at most MaxDependents.
// Ancestors and envelopes may narrow a grant further; the list says what
// would stop working without the connection, so it errs towards listing.
func grantedAgents(ctx context.Context, q *dbq.Queries, org ids.OrgID, conn dbq.PcConnection) ([]DependentAgent, error) {
	p, err := pinnedPackage(ctx, q, org, conn.Package)
	if errors.Is(err, ErrPackage) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	var ops []string
	for i := range p.Definitions {
		if len(servedRoutes(conn.Kind, &p.Definitions[i])) > 0 {
			ops = append(ops, p.Definitions[i].Operation)
		}
	}
	rows, err := q.ActiveGrantBounds(ctx, org)
	if err != nil {
		return nil, err
	}
	var out []DependentAgent
	for _, r := range rows {
		if len(out) == MaxDependents {
			break
		}
		if slices.ContainsFunc(out, func(a DependentAgent) bool { return a.Agent == r.AgentID }) {
			continue
		}
		b, err := gdomain.DecodeBounds(r.Bounds)
		if err != nil {
			continue // a grant that does not decode allows nothing
		}
		if b.Operations == nil || slices.ContainsFunc(ops, b.Operations.Matches) {
			out = append(out, DependentAgent{Agent: r.AgentID, Name: r.Name})
		}
	}
	return out, nil
}

func latest(ctx context.Context, q *dbq.Queries, org ids.OrgID, id ids.UUID, passedOnly bool) (*TestResult, error) {
	t, ok, err := lastTest(ctx, q, org, id, passedOnly)
	if !ok {
		return nil, err
	}
	return &t, err
}

// unlessEpoch is t, or the zero time for the epoch (none).
func unlessEpoch(t time.Time) time.Time {
	if t.Unix() == 0 {
		return time.Time{}
	}
	return t
}
