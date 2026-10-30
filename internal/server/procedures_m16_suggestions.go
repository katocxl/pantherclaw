// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"log/slog"
	"maps"

	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/automations/securitysteps"
	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	factspg "github.com/katocxl/pantherclaw/internal/facts/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/suggestions/adapters/suggestionsrpc"
	sgapp "github.com/katocxl/pantherclaw/internal/suggestions/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// suggestionProcedures are SuggestionService's procedures (G0 M16 D92):
// PostureService's permissions to list, read and dismiss, the policy-draft
// permission to draft. The use cases also require posture.read and
// grant.read where each suggestion's agent lives (HR-444).
var suggestionProcedures = map[string]td.Permission{
	pantherclawv1connect.SuggestionServiceListSuggestionsProcedure:     td.PermPostureRead,
	pantherclawv1connect.SuggestionServiceGetSuggestionProcedure:       td.PermPostureRead,
	pantherclawv1connect.SuggestionServiceDismissSuggestionProcedure:   td.PermPostureManage,
	pantherclawv1connect.SuggestionServiceDraftFromSuggestionProcedure: td.PermPolicyAuthor,
}

func init() { maps.Copy(procedurePermissions, suggestionProcedures) }

// registerSuggestions serves SuggestionService (D92) on the public API, as
// pc_app, on editions with PostureRemediation. Drafts are stored as the
// M11.1 create path stores a version and are never published (HR-442).
func registerSuggestions(rs *connect.Server, d apiDeps) {
	drafts := securitysteps.NewPolicyDrafts(&factspg.Store{Pool: d.pool}, &defspg.Store{Pool: d.pool}, d.cel)
	pantherclawv1connect.RegisterSuggestionServiceHandler(rs, suggestionsrpc.New(&sgapp.Service{
		Pool: d.pool, Ents: exposureEnts(d.billing), Drafts: drafts,
	}))
}

// registerSuggestionJobs adds the suggestion generation (D91), enqueued
// by each posture reconciliation in its own transaction.
func registerSuggestionJobs(reg *jobs.Registry, pool *db.Pool, log *slog.Logger) error {
	return sgapp.Register(reg, pool, log)
}
