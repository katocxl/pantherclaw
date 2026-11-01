// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"slices"
	"strconv"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	"github.com/katocxl/pantherclaw/internal/response/adapters/pgresponse"
	rdomain "github.com/katocxl/pantherclaw/internal/response/domain"
)

// ServerRevoke is a revoke of a catalogue server, expanded to the connections
// that match it when it runs (G0 M24 D224).
type ServerRevoke struct {
	Server      ids.UUID
	Connections []ids.UUID
	// Person is who confirmed it: the catalogue checked a person with a fresh
	// step-up and PreviewDigest in this transaction.
	Person        ids.UUID
	Reason        string
	PreviewDigest []byte
}

// ServerRevoked is what ContainServerIn added. With no connection it is
// empty: nothing needs reaching and nothing needs lifting.
type ServerRevoked struct {
	Action   ids.UUID
	Controls []ids.UUID
	Plans    []ids.UUID
}

// ContainServerIn adds one DENY_ALL connection control per connection under
// one action scoped to the server, raises the epoch, and requests the
// restoration of those controls, in plans of at most MaxPlanControls. The
// person who revoked is each plan's requester, so someone else decides it
// (HR-587). Only a person's revoke comes here: as a containment scope the
// server is refused (scopeOf), so no automation or SOAR request reaches it.
func (s *Containment) ContainServerIn(ctx context.Context, tx db.TenantTx, r ServerRevoke) (ServerRevoked, error) {
	if len(r.Connections) == 0 {
		return ServerRevoked{}, nil
	}
	org := tx.OrgID()
	actor, source, evActor, err := actorOf(reflexdomain.Subject{Type: reflexdomain.SubjectUser, ID: r.Person.String()})
	if err != nil {
		return ServerRevoked{}, err
	}
	reach := Preview{}
	for _, id := range r.Connections {
		p, err := preview(ctx, tx, org, rdomain.Control{ScopeType: rdomain.ScopeConnection, ScopeID: id.String(), Control: rdomain.DenyAll})
		if err != nil {
			return ServerRevoked{}, err
		}
		reach = widen(reach, p)
	}
	a := pgresponse.Action{
		ID: ids.NewV7(), Kind: rdomain.KindContain, ScopeType: rdomain.ScopeMcpServer, ScopeID: r.Server.String(), Control: rdomain.DenyAll,
		Reason: r.Reason, Actor: actor, Source: source, PreviewDigest: r.PreviewDigest, PreviewSummary: summaryOf(reach),
	}
	added, controls, err := pgresponse.AddConnectionControls(ctx, tx, org, a, r.Connections)
	if err != nil {
		return ServerRevoked{}, err
	}
	if err := planPaths(ctx, tx, a.ID, rdomain.KindContain, reach, added.Epoch); err != nil {
		return ServerRevoked{}, err
	}
	if _, err := s.settle(ctx, tx, org, a.ID); err != nil {
		return ServerRevoked{}, err
	}
	// One record per control, each naming it: the security log and a restore
	// read a control from its own record (M13, D264).
	for i, control := range controls {
		if err := recordAction(ctx, tx, evActor, "response.contain", a.ID, map[string]string{
			"action": a.ID.String(), "control_id": control.String(), "scope_type": rdomain.ScopeConnection, "scope": r.Connections[i].String(),
			"control": rdomain.DenyAll, "epoch": strconv.FormatInt(added.Epoch, 10), "source": source, "server": r.Server.String(),
		}, r.Reason); err != nil {
			return ServerRevoked{}, err
		}
	}
	out := ServerRevoked{Action: a.ID, Controls: controls}
	for part := range slices.Chunk(controls, MaxPlanControls) {
		plan, _, err := s.RequestRestorationIn(ctx, tx, RestorationRequest{
			Controls: part, Reason: "lift the revocation of MCP server " + r.Server.String(), Requester: r.Person,
		})
		if err != nil {
			return ServerRevoked{}, err
		}
		out.Plans = append(out.Plans, plan)
	}
	return out, nil
}

// widen adds what p reaches to w.
func widen(w, p Preview) Preview {
	w.Runs = union(w.Runs, p.Runs)
	w.Agents = union(w.Agents, p.Agents)
	w.Gateways = union(w.Gateways, p.Gateways)
	w.RunsOver = w.RunsOver || p.RunsOver
	w.Waiting += p.Waiting
	w.Alternatives = append(w.Alternatives, p.Alternatives...)
	w.Unknown = append(w.Unknown, p.Unknown...)
	return w
}

func union(a, b []ids.UUID) []ids.UUID {
	for _, x := range b {
		if !slices.Contains(a, x) {
			a = append(a, x)
		}
	}
	return a
}

// serverRevocation reports whether an action is a catalogue server's revoke.
// Its control on a connection that is not ACTIVE only ends a block: the
// connection stays as it is, the server stays REVOKED and activating the
// connection is refused, so nothing starts running on the lift (G0 M24 D265).
func serverRevocation(ctx context.Context, q *dbq.Queries, org ids.OrgID, action ids.UUID) (bool, error) {
	a, err := q.GetResponseAction(ctx, org, action)
	if err != nil {
		return false, err
	}
	return a.ScopeType == rdomain.ScopeMcpServer, nil
}
