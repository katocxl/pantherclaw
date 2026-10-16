// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package search

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"time"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// runner pages and counts one entity inside the viewer's scope.
type runner struct {
	page  func(context.Context, *Service, tenancy.Caller, db.TenantTx, Scope, Filters, page.Request) ([]Item, string, error)
	count func(context.Context, *Service, tenancy.Caller, db.TenantTx, Scope, Filters) (int, error)
}

var runners = map[Entity]runner{
	EntityTransactions: {pageTransactions, countTransactions},
	EntityRuns:         {pageRuns, countRuns},
	EntityAgents:       {pageAgents, countAgents},
	EntityGrants:       {pageGrants, countGrants},
	EntityGrantChanges: {pageGrantChanges, countGrantChanges},
	EntityConnections:  {pageConnections, countConnections},
	EntityApprovals:    {pageApprovals, countApprovals},
	EntityAudit:        {pageAudit, countAudit},
	EntityOperations:   {pageOperations, countOperations},
}

func before(pr page.Request) *ids.UUID {
	if pr.After.IsZero() {
		return nil
	}
	a := pr.After
	return &a
}

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func idStr(p *ids.UUID) string {
	if p == nil {
		return ""
	}
	return p.String()
}

func ts(p *time.Time) string {
	if p == nil {
		return ""
	}
	return p.UTC().Format(time.RFC3339Nano)
}

// fields drops empty values.
func fields(kv ...string) map[string]string {
	m := make(map[string]string, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] != "" {
			m[kv[i]] = kv[i+1]
		}
	}
	return m
}

// transactionLabel separates enforced decisions from shadow (monitor-mode)
// predictions, and an allowed attempt from an effect confirmed at the
// target (F306, F314).
func transactionLabel(mode, decision string, effect *string) string {
	switch {
	case mode == "monitor":
		return "SHADOW"
	case decision != "ALLOW":
		return "ENFORCED"
	case effect != nil && *effect == "CONFIRMED":
		return "CONFIRMED"
	default:
		return "ATTEMPT"
	}
}

func txParams(c tenancy.Caller, sc Scope, f Filters) dbq.SearchTransactionsParams {
	return dbq.SearchTransactionsParams{
		OrgID: c.Org, AllAgents: sc.All, Agents: sc.agentList(), ID: f.ID, AgentID: f.Agent, RunID: f.Run,
		ConnectionID: f.Connection, GrantID: f.Grant, PrincipalUserID: f.PrincipalUser, PrincipalSaID: f.PrincipalSA,
		Operation: f.Operation, OperationPrefix: f.OperationPrefix, TargetType: f.TargetType,
		Decisions: list(f.Decisions), Modes: list(f.Modes), EnvironmentKinds: list(f.EnvKinds),
		StartTime: f.Start, EndTime: f.End,
	}
}

func pageTransactions(ctx context.Context, _ *Service, c tenancy.Caller, tx db.TenantTx, sc Scope, f Filters, pr page.Request) ([]Item, string, error) {
	p := txParams(c, sc, f)
	p.Before, p.PageLimit = before(pr), pr.Limit()
	rows, err := dbq.New(tx).SearchTransactions(ctx, p)
	if err != nil {
		return nil, "", err
	}
	rows, next := page.Finish(pr, rows, func(r dbq.SearchTransactionsRow) ids.UUID { return r.ID })
	items := make([]Item, 0, len(rows))
	for _, r := range rows {
		items = append(items, Item{
			Entity: EntityTransactions, ID: r.ID.String(), Time: r.CreatedAt,
			Label: transactionLabel(r.Mode, r.Decision, r.EffectState),
			Fields: fields("run", r.RunID.String(), "agent", r.AgentID.String(), "operation", r.Operation,
				"connection", idStr(r.ConnectionID), "decision", r.Decision, "reason", r.ReasonCode, "mode", r.Mode,
				"effect_state", str(r.EffectState), "target_type", str(r.TargetType), "target_id", str(r.TargetID),
				"environment_kind", r.EnvironmentKind, "simulated", strconv.FormatBool(r.Simulated)),
			Evidence: []string{"transaction:" + r.ID.String(), "run:" + r.RunID.String()},
		})
	}
	return items, next, nil
}

func countTransactions(ctx context.Context, _ *Service, c tenancy.Caller, tx db.TenantTx, sc Scope, f Filters) (int, error) {
	p := txParams(c, sc, f)
	n, err := dbq.New(tx).CountTransactions(ctx, dbq.CountTransactionsParams{
		OrgID: p.OrgID, AllAgents: p.AllAgents, Agents: p.Agents, ID: p.ID, AgentID: p.AgentID, RunID: p.RunID,
		ConnectionID: p.ConnectionID, GrantID: p.GrantID, PrincipalUserID: p.PrincipalUserID, PrincipalSaID: p.PrincipalSaID,
		Operation: p.Operation, OperationPrefix: p.OperationPrefix, TargetType: p.TargetType, Decisions: p.Decisions,
		Modes: p.Modes, EnvironmentKinds: p.EnvironmentKinds, StartTime: p.StartTime, EndTime: p.EndTime,
	})
	return int(n), err
}

func pageRuns(ctx context.Context, _ *Service, c tenancy.Caller, tx db.TenantTx, sc Scope, f Filters, pr page.Request) ([]Item, string, error) {
	rows, err := dbq.New(tx).SearchRuns(ctx, dbq.SearchRunsParams{
		OrgID: c.Org, AllAgents: sc.All, Agents: sc.agentList(), Before: before(pr), ID: f.ID, AgentID: f.Agent,
		GrantID: f.Grant, PrincipalUserID: f.PrincipalUser, PrincipalSaID: f.PrincipalSA, States: list(f.States),
		StartTime: f.Start, EndTime: f.End, PageLimit: pr.Limit(),
	})
	if err != nil {
		return nil, "", err
	}
	rows, next := page.Finish(pr, rows, func(r dbq.SearchRunsRow) ids.UUID { return r.ID })
	items := make([]Item, 0, len(rows))
	for _, r := range rows {
		items = append(items, Item{
			Entity: EntityRuns, ID: r.ID.String(), Time: r.CreatedAt, Label: r.State,
			Fields: fields("agent", r.AgentID.String(), "parent_run", idStr(r.ParentRunID), "grant", idStr(r.GrantID),
				"principal_user", idStr(r.PrincipalUserID), "principal_service_account", idStr(r.PrincipalSaID),
				"launcher_user", idStr(r.LauncherUserID), "launcher_service_account", idStr(r.LauncherSaID),
				"state", r.State, "ended_at", ts(r.EndedAt), "simulated", strconv.FormatBool(r.Simulated)),
			Evidence: []string{"run:" + r.ID.String()},
		})
	}
	return items, next, nil
}

func countRuns(ctx context.Context, _ *Service, c tenancy.Caller, tx db.TenantTx, sc Scope, f Filters) (int, error) {
	n, err := dbq.New(tx).CountRuns(ctx, dbq.CountRunsParams{
		OrgID: c.Org, AllAgents: sc.All, Agents: sc.agentList(), ID: f.ID, AgentID: f.Agent, GrantID: f.Grant,
		PrincipalUserID: f.PrincipalUser, PrincipalSaID: f.PrincipalSA, States: list(f.States), StartTime: f.Start, EndTime: f.End,
	})
	return int(n), err
}

func pageAgents(ctx context.Context, _ *Service, c tenancy.Caller, tx db.TenantTx, sc Scope, f Filters, pr page.Request) ([]Item, string, error) {
	rows, err := dbq.New(tx).SearchAgents(ctx, dbq.SearchAgentsParams{
		OrgID: c.Org, AllAgents: sc.All, Agents: sc.agentList(), Before: before(pr), ID: f.ID, TeamID: f.Team,
		States: list(f.States), EnvironmentKinds: list(f.EnvKinds), UsedConnectionID: f.UsedConnection,
		StartTime: f.Start, EndTime: f.End, PageLimit: pr.Limit(),
	})
	if err != nil {
		return nil, "", err
	}
	rows, next := page.Finish(pr, rows, func(r dbq.SearchAgentsRow) ids.UUID { return r.ID })
	items := make([]Item, 0, len(rows))
	for _, r := range rows {
		items = append(items, Item{
			Entity: EntityAgents, ID: r.ID.String(), Time: r.CreatedAt, Label: r.State,
			Fields: fields("name", r.Name, "state", r.State, "team", idStr(r.TeamID), "environment", idStr(r.EnvironmentID),
				"environment_kind", str(r.EnvironmentKind), "owner", idStr(r.OwnerUserID)),
			Evidence: []string{"agent:" + r.ID.String()},
		})
	}
	return items, next, nil
}

func countAgents(ctx context.Context, _ *Service, c tenancy.Caller, tx db.TenantTx, sc Scope, f Filters) (int, error) {
	n, err := dbq.New(tx).CountAgents(ctx, dbq.CountAgentsParams{
		OrgID: c.Org, AllAgents: sc.All, Agents: sc.agentList(), ID: f.ID, TeamID: f.Team, States: list(f.States),
		EnvironmentKinds: list(f.EnvKinds), UsedConnectionID: f.UsedConnection, StartTime: f.Start, EndTime: f.End,
	})
	return int(n), err
}

func pageGrants(ctx context.Context, _ *Service, c tenancy.Caller, tx db.TenantTx, sc Scope, f Filters, pr page.Request) ([]Item, string, error) {
	rows, err := dbq.New(tx).SearchGrants(ctx, dbq.SearchGrantsParams{
		OrgID: c.Org, AllAgents: sc.All, Agents: sc.agentList(), Before: before(pr), ID: f.ID, AgentID: f.Agent,
		PrincipalUserID: f.PrincipalUser, PrincipalSaID: f.PrincipalSA, States: list(f.States),
		StartTime: f.Start, EndTime: f.End, UnusedSince: f.UnusedSince, PageLimit: pr.Limit(),
	})
	if err != nil {
		return nil, "", err
	}
	rows, next := page.Finish(pr, rows, func(r dbq.SearchGrantsRow) ids.UUID { return r.ID })
	items := make([]Item, 0, len(rows))
	for _, r := range rows {
		items = append(items, Item{
			Entity: EntityGrants, ID: r.ID.String(), Time: r.CreatedAt, Label: r.State,
			Fields: fields("agent", r.AgentID.String(), "principal_user", idStr(r.PrincipalUserID),
				"principal_service_account", idStr(r.PrincipalSaID), "environment", r.EnvironmentID.String(),
				"parent", idStr(r.ParentID), "depth", strconv.Itoa(int(r.Depth)), "state", r.State,
				"revision", strconv.Itoa(int(r.CurrentRevision)), "grantor_kind", r.GrantorKind,
				"grantor", r.GrantorID.String(), "revoked_at", ts(r.RevokedAt)),
			Evidence: []string{"grant:" + r.ID.String()},
		})
	}
	return items, next, nil
}

func countGrants(ctx context.Context, _ *Service, c tenancy.Caller, tx db.TenantTx, sc Scope, f Filters) (int, error) {
	n, err := dbq.New(tx).CountGrants(ctx, dbq.CountGrantsParams{
		OrgID: c.Org, AllAgents: sc.All, Agents: sc.agentList(), ID: f.ID, AgentID: f.Agent,
		PrincipalUserID: f.PrincipalUser, PrincipalSaID: f.PrincipalSA, States: list(f.States),
		StartTime: f.Start, EndTime: f.End, UnusedSince: f.UnusedSince,
	})
	return int(n), err
}

// grantChangeLabel separates material scope changes (a new grant or a
// revision that widens it) from narrowing or metadata revisions (F315).
func grantChangeLabel(revision int32, widens bool) string {
	switch {
	case revision == 1:
		return "NEW_GRANT"
	case widens:
		return "MATERIAL"
	default:
		return "NARROWING_OR_METADATA"
	}
}

func pageGrantChanges(ctx context.Context, _ *Service, c tenancy.Caller, tx db.TenantTx, sc Scope, f Filters, pr page.Request) ([]Item, string, error) {
	rows, err := dbq.New(tx).SearchGrantRevisions(ctx, dbq.SearchGrantRevisionsParams{
		OrgID: c.Org, AllAgents: sc.All, Agents: sc.agentList(), Before: before(pr), AgentID: f.Agent, GrantID: f.Grant,
		WidensOnly: f.WidensOnly, StartTime: f.Start, EndTime: f.End, PageLimit: pr.Limit(),
	})
	if err != nil {
		return nil, "", err
	}
	rows, next := page.Finish(pr, rows, func(r dbq.SearchGrantRevisionsRow) ids.UUID { return r.ID })
	items := make([]Item, 0, len(rows))
	for _, r := range rows {
		items = append(items, Item{
			Entity: EntityGrantChanges, ID: r.ID.String(), Time: r.CreatedAt, Label: grantChangeLabel(r.Revision, r.Widens),
			Fields: fields("grant", r.GrantID.String(), "agent", r.AgentID.String(), "revision", strconv.Itoa(int(r.Revision)),
				"widens", strconv.FormatBool(r.Widens), "created_by", r.CreatedBy, "expires_at", ts(&r.ExpiresAt)),
			Evidence: []string{"grant:" + r.GrantID.String()},
		})
	}
	return items, next, nil
}

func countGrantChanges(ctx context.Context, _ *Service, c tenancy.Caller, tx db.TenantTx, sc Scope, f Filters) (int, error) {
	n, err := dbq.New(tx).CountGrantRevisions(ctx, dbq.CountGrantRevisionsParams{
		OrgID: c.Org, AllAgents: sc.All, Agents: sc.agentList(), AgentID: f.Agent, GrantID: f.Grant,
		WidensOnly: f.WidensOnly, StartTime: f.Start, EndTime: f.End,
	})
	return int(n), err
}

func pageConnections(ctx context.Context, _ *Service, c tenancy.Caller, tx db.TenantTx, _ Scope, f Filters, pr page.Request) ([]Item, string, error) {
	rows, err := dbq.New(tx).SearchConnections(ctx, dbq.SearchConnectionsParams{
		OrgID: c.Org, Before: before(pr), ID: f.ID, GatewayID: f.Gateway, States: list(f.States), Kinds: list(f.Kinds),
		AccessModes: list(f.AccessModes), StartTime: f.Start, EndTime: f.End, PageLimit: pr.Limit(),
	})
	if err != nil {
		return nil, "", err
	}
	rows, next := page.Finish(pr, rows, func(r dbq.SearchConnectionsRow) ids.UUID { return r.ID })
	items := make([]Item, 0, len(rows))
	for _, r := range rows {
		items = append(items, Item{
			Entity: EntityConnections, ID: r.ID.String(), Time: r.CreatedAt, Label: r.State,
			Fields: fields("name", r.Name, "kind", r.Kind, "gateway", r.GatewayID.String(), "package", r.Package,
				"destination_class", r.DestinationClass, "access_mode", r.AccessMode, "default_mode", r.DefaultMode,
				"state", r.State, "simulated", strconv.FormatBool(r.Simulated)),
			Evidence: []string{"connection:" + r.ID.String()},
		})
	}
	return items, next, nil
}

func countConnections(ctx context.Context, _ *Service, c tenancy.Caller, tx db.TenantTx, _ Scope, f Filters) (int, error) {
	n, err := dbq.New(tx).CountConnections(ctx, dbq.CountConnectionsParams{
		OrgID: c.Org, ID: f.ID, GatewayID: f.Gateway, States: list(f.States), Kinds: list(f.Kinds),
		AccessModes: list(f.AccessModes), StartTime: f.Start, EndTime: f.End,
	})
	return int(n), err
}

func pageApprovals(ctx context.Context, _ *Service, c tenancy.Caller, tx db.TenantTx, sc Scope, f Filters, pr page.Request) ([]Item, string, error) {
	rows, err := dbq.New(tx).SearchApprovals(ctx, dbq.SearchApprovalsParams{
		OrgID: c.Org, AllAgents: sc.All, Agents: sc.agentList(), Before: before(pr), ID: f.ID, AgentID: f.Agent,
		RunID: f.Run, Operation: f.Operation, States: list(f.States), StartTime: f.Start, EndTime: f.End, PageLimit: pr.Limit(),
	})
	if err != nil {
		return nil, "", err
	}
	rows, next := page.Finish(pr, rows, func(r dbq.SearchApprovalsRow) ids.UUID { return r.ID })
	items := make([]Item, 0, len(rows))
	for _, r := range rows {
		ev := []string{"approval:" + r.ID.String()}
		if r.TransactionID != nil {
			ev = append(ev, "transaction:"+r.TransactionID.String())
		}
		items = append(items, Item{
			Entity: EntityApprovals, ID: r.ID.String(), Time: r.CreatedAt, Label: r.State,
			Fields: fields("agent", idStr(r.AgentID), "run", idStr(r.RunID), "transaction", idStr(r.TransactionID),
				"operation", r.Operation, "state", r.State, "end_reason", str(r.EndReason),
				"deadline", ts(&r.DeadlineAt), "ended_at", ts(r.EndedAt)),
			Evidence: ev,
		})
	}
	return items, next, nil
}

func countApprovals(ctx context.Context, _ *Service, c tenancy.Caller, tx db.TenantTx, sc Scope, f Filters) (int, error) {
	n, err := dbq.New(tx).CountApprovals(ctx, dbq.CountApprovalsParams{
		OrgID: c.Org, AllAgents: sc.All, Agents: sc.agentList(), ID: f.ID, AgentID: f.Agent, RunID: f.Run,
		Operation: f.Operation, States: list(f.States), StartTime: f.Start, EndTime: f.End,
	})
	return int(n), err
}

func pageAudit(ctx context.Context, _ *Service, c tenancy.Caller, tx db.TenantTx, _ Scope, f Filters, pr page.Request) ([]Item, string, error) {
	rows, err := dbq.New(tx).SearchAudit(ctx, dbq.SearchAuditParams{
		OrgID: c.Org, Before: before(pr), ID: f.ID, KindPrefix: f.KindPrefix, ActorID: f.Actor,
		StartTime: f.Start, EndTime: f.End, PageLimit: pr.Limit(),
	})
	if err != nil {
		return nil, "", err
	}
	rows, next := page.Finish(pr, rows, func(r dbq.SearchAuditRow) ids.UUID { return r.ID })
	items := make([]Item, 0, len(rows))
	for _, r := range rows {
		seq := ""
		if r.Seq.Valid {
			seq = strconv.FormatInt(r.Seq.Int64, 10)
		}
		items = append(items, Item{
			Entity: EntityAudit, ID: r.ID.String(), Time: r.OccurredAt, Label: r.Kind,
			Fields:   fields("kind", r.Kind, "actor_type", r.ActorType, "actor", r.ActorID, "seq", seq),
			Evidence: []string{"ledger:" + r.ID.String()},
		})
	}
	return items, next, nil
}

func countAudit(ctx context.Context, _ *Service, c tenancy.Caller, tx db.TenantTx, _ Scope, f Filters) (int, error) {
	n, err := dbq.New(tx).CountAudit(ctx, dbq.CountAuditParams{
		OrgID: c.Org, ID: f.ID, KindPrefix: f.KindPrefix, ActorID: f.Actor, StartTime: f.Start, EndTime: f.End,
	})
	return int(n), err
}

// capability labels an operation for tool-capability search (F309):
// VERIFIED when its effects rest on observed or documented review that has
// not expired, DECLARED when they are only declared, UNCLASSIFIED when the
// definition names no effect at all.
func capability(d *defs.Definition, now time.Time) string {
	if len(d.Effects) == 0 && len(d.SideEffects) == 0 {
		return "UNCLASSIFIED"
	}
	exp, err := d.Assurance.Expiry()
	if err == nil && now.Before(exp) && (d.Assurance.Basis == defs.BasisObserved || d.Assurance.Basis == defs.BasisDocumented) {
		return "VERIFIED"
	}
	return "DECLARED"
}

// operationMatches reports whether d matches f: an exact operation, and an
// effect kind prefix met by a direct or side effect. An unclassified
// operation matches every effect prefix, since it may have any effect.
func operationMatches(d *defs.Definition, f Filters) bool {
	if f.Operation != "" && d.Operation != f.Operation {
		return false
	}
	if f.EffectPrefix == "" || (len(d.Effects) == 0 && len(d.SideEffects) == 0) {
		return true
	}
	for _, e := range slices.Concat(d.Effects, d.SideEffects) {
		if strings.HasPrefix(e.Kind, f.EffectPrefix) {
			return true
		}
	}
	return false
}

// operations returns the org's active operations matching f, sorted by
// operation name.
func (s *Service) operations(ctx context.Context, c tenancy.Caller, tx db.TenantTx, f Filters) ([]*defs.Definition, error) {
	if s.Defs == nil {
		return nil, ErrNoDefinitions
	}
	all, err := s.Defs.ActiveDefinitionsInTx(ctx, tx, c.Org)
	if err != nil {
		return nil, err
	}
	var out []*defs.Definition
	for _, d := range all {
		if operationMatches(d, f) {
			out = append(out, d)
		}
	}
	slices.SortFunc(out, func(a, b *defs.Definition) int { return strings.Compare(a.Operation, b.Operation) })
	return slices.CompactFunc(out, func(a, b *defs.Definition) bool { return a.Operation == b.Operation }), nil
}

// maxOpPage bounds the operations listed; Count gives the full number.
const maxOpPage = page.Max

func pageOperations(ctx context.Context, s *Service, c tenancy.Caller, tx db.TenantTx, _ Scope, f Filters, pr page.Request) ([]Item, string, error) {
	if !pr.After.IsZero() {
		return nil, "", page.ErrBadToken // the catalog fits in one page
	}
	ops, err := s.operations(ctx, c, tx, f)
	if err != nil {
		return nil, "", err
	}
	now := s.now()
	items := make([]Item, 0, min(len(ops), maxOpPage))
	for _, d := range ops[:min(len(ops), maxOpPage)] {
		kinds := make([]string, 0, len(d.Effects)+len(d.SideEffects))
		for _, e := range slices.Concat(d.Effects, d.SideEffects) {
			kinds = append(kinds, e.Kind)
		}
		items = append(items, Item{
			Entity: EntityOperations, ID: d.Operation, Label: capability(d, now),
			Fields: fields("operation", d.Operation, "access", string(d.Access), "effects", strings.Join(kinds, ","),
				"reversibility", string(d.Reversibility), "assurance", string(d.Assurance.Basis),
				"valid_until", d.Assurance.ValidUntil, "digest", d.Digest),
			Evidence: []string{"definition:" + d.Digest},
		})
	}
	return items, "", nil
}

func countOperations(ctx context.Context, s *Service, c tenancy.Caller, tx db.TenantTx, _ Scope, f Filters) (int, error) {
	ops, err := s.operations(ctx, c, tx, f)
	return len(ops), err
}
