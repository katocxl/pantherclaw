// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package authority

import (
	"context"
	"errors"
	"fmt"

	"github.com/katocxl/pantherclaw/internal/actionir"
	approvals "github.com/katocxl/pantherclaw/internal/approvals/app"
	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Narrower checks a decider's narrower proposal against the held action
// and simulates it through the pipeline, recording nothing (G0 M5 part 2,
// HR-172, F147). It implements the approvals Simulator.
type Narrower struct {
	Pipeline *pipeline.Pipeline
	Pool     *db.Pool
}

var _ approvals.Simulator = (*Narrower)(nil)

// Narrow implements approvals.Simulator: the proposal is the held action's
// parameters with material ones narrowed; the simulated action is the held
// one with those parameters and a new action id, decided for the held
// action's instance through its connection's gateway.
func (n *Narrower) Narrow(ctx context.Context, org ids.OrgID, held, proposed []byte) (approvals.Simulation, error) {
	h, err := actionir.Parse(held)
	if err != nil {
		return approvals.Simulation{}, fmt.Errorf("authority: the held action does not parse: %w", err)
	}
	a := h.Action
	pinned, err := n.Pipeline.Reader.Definition(ctx, org, a.Definition)
	if err != nil {
		return approvals.Simulation{}, fmt.Errorf("authority: the held action's definition: %w", err)
	}
	d := pinned.Definition
	was, err := d.DecodeParams(a.Params)
	if err != nil {
		return approvals.Simulation{}, err
	}
	now, err := d.DecodeParams(proposed)
	if err != nil {
		return approvals.Simulation{}, errors.Join(apdomain.ErrNotNarrower, err)
	}
	if err := apdomain.CheckNarrower(d, was, now); err != nil {
		return approvals.Simulation{}, err
	}
	params, err := d.EncodeParams(now)
	if err != nil {
		return approvals.Simulation{}, errors.Join(apdomain.ErrNotNarrower, err)
	}
	b := a
	b.Params, b.ActionID, b.DedupeKey = params, ids.NewV7().String(), ""
	p, err := actionir.Encode(b)
	if err != nil {
		return approvals.Simulation{}, errors.Join(apdomain.ErrNotNarrower, err)
	}
	req := pipeline.Request{Org: org, Action: p}
	instance, err := ids.ParseUUID(a.AgentInstance)
	if err != nil {
		return approvals.Simulation{}, err
	}
	if err := n.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		i, err := dbq.New(tx).GetInstance(ctx, org, instance)
		if err != nil {
			return err
		}
		req.Identity = pipeline.Identity{InstanceID: i.ID, AgentID: i.AgentID, AttestationLevel: int(i.AttLevel), JKT: i.Jkt}
		return nil
	}, db.ReadOnly()); err != nil {
		return approvals.Simulation{}, err
	}
	if a.Connection != "" {
		conn, err := ids.ParseUUID(a.Connection)
		if err != nil {
			return approvals.Simulation{}, err
		}
		c, err := n.Pipeline.Reader.Connection(ctx, org, conn)
		if err != nil {
			return approvals.Simulation{}, err
		}
		req.Gateway = c.Gateway.String()
	}
	ev, err := n.Pipeline.Evaluate(ctx, req)
	if err != nil {
		return approvals.Simulation{}, err
	}
	out := approvals.Simulation{Params: params, Decision: string(ev.Decision)}
	for _, it := range ev.Checklist {
		if it.Decisive || it.Status == pipeline.StatusFailed || it.Status == pipeline.StatusMissing || it.Status == pipeline.StatusRequired {
			out.Reasons = append(out.Reasons, approvals.Reason{Code: it.Code, Check: it.Check, Detail: it.Detail, Decisive: it.Decisive})
		}
	}
	return out, nil
}
