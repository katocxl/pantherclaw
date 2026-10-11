// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"time"

	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
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
// time; a zero time is none.
type Deliveries struct {
	Since                    time.Time
	Failed, Unknown          int32
	LastFailure, LastSuccess time.Time
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
	// Agents depend on it; AgentsHidden: the caller may not read agents
	// org-wide, so none are listed.
	Agents       []DependentAgent
	AgentsHidden bool
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
		if !seesAgents {
			return nil
		}
		agents, err := q.ConnectionDependentAgents(ctx, dbq.ConnectionDependentAgentsParams{
			OrgID: c.Org, ConnectionID: &id, Since: now.Add(-DependentWindow), MaxRows: MaxDependents,
		})
		for _, a := range agents {
			out.Agents = append(out.Agents, DependentAgent{Agent: a.AgentID, Name: a.Name, LastUsed: a.LastUsedAt})
		}
		return err
	})
	return out, err
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
