// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package packsrpc serves PackService over Connect (G0 M11 part 2, D41).
// Handlers only translate; the use cases check the caller.
package packsrpc

import (
	"context"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/policy/packs"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Handler serves PackService.
type Handler struct {
	pantherclawv1connect.UnimplementedPackServiceHandler
	svc *packs.Service
}

// New returns the PackService handler.
func New(svc *packs.Service) *Handler { return &Handler{svc: svc} }

var errID = pcerr.New(pcerr.InvalidArgument, "INVALID_ID", "an id is not a UUID")

func packPB(p packs.Pack) *pantherclawv1.Pack {
	return &pantherclawv1.Pack{
		Name: p.Name, Summary: p.Summary, Template: p.Template, Covers: p.Covers, Parameters: p.Needs(),
		BaselineTtlSeconds: int32(p.BaselineTTLSeconds), AutomationTemplate: p.AutomationTemplate, //nolint:gosec // ≤ 90 days
	}
}

// reader checks policy.read at the org: packs are policy content.
func reader(ctx context.Context) error {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return err
	}
	return c.Require(td.PermPolicyRead, td.OrgPath(c.Org))
}

// ListPacks implements PackServiceHandler.
func (h *Handler) ListPacks(ctx context.Context, _ *pantherclawv1.ListPacksRequest) (*pantherclawv1.ListPacksResponse, error) {
	if err := reader(ctx); err != nil {
		return nil, err
	}
	ps, err := packs.List()
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ListPacksResponse{}
	for _, p := range ps {
		out.Packs = append(out.Packs, packPB(p))
	}
	return out, nil
}

// GetPack implements PackServiceHandler.
func (h *Handler) GetPack(ctx context.Context, r *pantherclawv1.GetPackRequest) (*pantherclawv1.GetPackResponse, error) {
	if err := reader(ctx); err != nil {
		return nil, err
	}
	p, err := packs.Get(r.GetName())
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetPackResponse{Pack: packPB(p)}, nil
}

// ApplyPack implements PackServiceHandler.
func (h *Handler) ApplyPack(ctx context.Context, r *pantherclawv1.ApplyPackRequest) (*pantherclawv1.ApplyPackResponse, error) {
	in := packs.Apply{Pack: r.GetName(), Parameters: r.GetParameters()}
	var err error
	if in.Environment, err = ids.ParseUUID(r.GetEnvironmentId()); err != nil {
		return nil, errID
	}
	for _, a := range r.GetAgentIds() {
		id, err := ids.ParseUUID(a)
		if err != nil {
			return nil, errID
		}
		in.Agents = append(in.Agents, id)
	}
	if r.GetCohortId() != "" {
		id, err := ids.ParseUUID(r.GetCohortId())
		if err != nil {
			return nil, errID
		}
		in.Cohort = &id
	}
	res, err := h.svc.ApplyPack(ctx, in)
	if err != nil {
		return nil, err
	}
	out := &pantherclawv1.ApplyPackResponse{
		PolicyVersionId: res.Version.ID.String(), PolicyVersion: int32(res.Version.Version), //nolint:gosec // versions are small
		Added: res.Added, Replaced: res.Replaced, Unchanged: res.Unchanged, Skipped: res.Skipped,
	}
	for _, b := range res.Baselines {
		out.Baselines = append(out.Baselines, &pantherclawv1.PackBaseline{
			AgentId: b.Agent.String(), TaskRef: b.TaskRef, Bounds: b.Bounds, Limits: b.Limits, TtlSeconds: int32(b.TTLSeconds), //nolint:gosec // ≤ 90 days
		})
	}
	return out, nil
}
