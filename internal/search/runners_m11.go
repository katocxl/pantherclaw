// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package search

import (
	"context"
	"strconv"
	"strings"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The entities G0 M11 part 2 adds (D44): alerts, incidents, cases and
// posture findings at the viewer's agent scope; policy versions, packages
// and gateways at the org.

func init() {
	runners[EntityAlerts] = runner{pageAlerts, countAlerts}
	runners[EntityIncidents] = runner{pageIncidents, countIncidents}
	runners[EntityCases] = runner{pageCases, countCases}
	runners[EntityFindings] = runner{pageFindings, countFindings}
	runners[EntityPolicyVersions] = runner{pagePolicyVersions, countPolicyVersions}
	runners[EntityPackages] = runner{pagePackages, countPackages}
	runners[EntityGateways] = runner{pageGateways, countGateways}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return ""
}

func alertParams(c tenancy.Caller, sc Scope, f Filters) dbq.SearchAlertsParams {
	return dbq.SearchAlertsParams{
		OrgID: c.Org, AllAgents: sc.All, Agents: sc.agentList(), ID: f.ID, AgentID: f.Agent, IncidentID: f.Incident,
		States: list(f.States), Severities: list(f.Severities), Sources: list(f.Kinds), StartTime: f.Start, EndTime: f.End,
	}
}

func pageAlerts(ctx context.Context, _ *Service, c tenancy.Caller, tx db.TenantTx, sc Scope, f Filters, pr page.Request) ([]Item, string, error) {
	p := alertParams(c, sc, f)
	p.Before, p.PageLimit = before(pr), pr.Limit()
	rows, err := dbq.New(tx).SearchAlerts(ctx, p)
	if err != nil {
		return nil, "", err
	}
	rows, next := page.Finish(pr, rows, func(r dbq.SearchAlertsRow) ids.UUID { return r.ID })
	items := make([]Item, 0, len(rows))
	for _, r := range rows {
		ev := []string{"alert:" + r.ID.String()}
		if r.IncidentID != nil {
			ev = append(ev, "incident:"+r.IncidentID.String())
		}
		items = append(items, Item{
			Entity: EntityAlerts, ID: r.ID.String(), Time: r.CreatedAt, Label: r.State,
			Fields: fields("title", r.Title, "source", r.Source, "rule", r.RuleID, "severity", r.Severity,
				"attention", r.Attention, "basis", r.Basis, "state", r.State, "incident", idStr(r.IncidentID),
				"count", strconv.Itoa(int(r.Count)), "first_seen", ts(&r.FirstSeen), "last_seen", ts(&r.LastSeen),
				"agents", strings.Join(r.Agents, ","), "agent", single(r.Agents), "test", boolStr(r.Test)),
			Evidence: ev,
		})
	}
	return items, next, nil
}

func countAlerts(ctx context.Context, _ *Service, c tenancy.Caller, tx db.TenantTx, sc Scope, f Filters) (int, error) {
	p := alertParams(c, sc, f)
	n, err := dbq.New(tx).CountAlerts(ctx, dbq.CountAlertsParams{
		OrgID: p.OrgID, AllAgents: p.AllAgents, Agents: p.Agents, ID: p.ID, AgentID: p.AgentID, IncidentID: p.IncidentID,
		States: p.States, Severities: p.Severities, Sources: p.Sources, StartTime: p.StartTime, EndTime: p.EndTime,
	})
	return int(n), err
}

func pageIncidents(ctx context.Context, _ *Service, c tenancy.Caller, tx db.TenantTx, sc Scope, f Filters, pr page.Request) ([]Item, string, error) {
	rows, err := dbq.New(tx).SearchIncidents(ctx, dbq.SearchIncidentsParams{
		OrgID: c.Org, AllAgents: sc.All, Agents: sc.agentList(), Before: before(pr), ID: f.ID, AgentID: f.Agent,
		States: list(f.States), Severities: list(f.Severities), StartTime: f.Start, EndTime: f.End, PageLimit: pr.Limit(),
	})
	if err != nil {
		return nil, "", err
	}
	rows, next := page.Finish(pr, rows, func(r dbq.SearchIncidentsRow) ids.UUID { return r.ID })
	items := make([]Item, 0, len(rows))
	for _, r := range rows {
		items = append(items, Item{
			Entity: EntityIncidents, ID: r.ID.String(), Time: r.CreatedAt, Label: r.State,
			Fields: fields("title", r.Title, "severity", r.Severity, "state", r.State, "owner", idStr(r.OwnerID),
				"opened_by", r.OpenedBy, "agents", strings.Join(r.Agents, ","), "agent", single(r.Agents), "updated_at", ts(&r.UpdatedAt),
				"test", boolStr(r.Test)),
			Evidence: []string{"incident:" + r.ID.String()},
		})
	}
	return items, next, nil
}

func countIncidents(ctx context.Context, _ *Service, c tenancy.Caller, tx db.TenantTx, sc Scope, f Filters) (int, error) {
	n, err := dbq.New(tx).CountIncidents(ctx, dbq.CountIncidentsParams{
		OrgID: c.Org, AllAgents: sc.All, Agents: sc.agentList(), ID: f.ID, AgentID: f.Agent,
		States: list(f.States), Severities: list(f.Severities), StartTime: f.Start, EndTime: f.End,
	})
	return int(n), err
}

func pageCases(ctx context.Context, _ *Service, c tenancy.Caller, tx db.TenantTx, sc Scope, f Filters, pr page.Request) ([]Item, string, error) {
	rows, err := dbq.New(tx).SearchCases(ctx, dbq.SearchCasesParams{
		OrgID: c.Org, AllAgents: sc.All, Agents: sc.agentList(), Before: before(pr), ID: f.ID, AgentID: f.Agent,
		AlertID: f.Alert, IncidentID: f.Incident, States: list(f.States), StartTime: f.Start, EndTime: f.End,
		PageLimit: pr.Limit(),
	})
	if err != nil {
		return nil, "", err
	}
	rows, next := page.Finish(pr, rows, func(r dbq.SearchCasesRow) ids.UUID { return r.ID })
	items := make([]Item, 0, len(rows))
	for _, r := range rows {
		items = append(items, Item{
			Entity: EntityCases, ID: r.ID.String(), Time: r.CreatedAt, Label: r.State,
			Fields: fields("title", r.Title, "source", r.Source, "state", r.State, "owner", idStr(r.OwnerID),
				"alert", idStr(r.AlertID), "incident", idStr(r.IncidentID), "disposition", str(r.Disposition),
				"impact", str(r.Impact), "closed_at", ts(r.ClosedAt), "agents", strings.Join(r.Agents, ","),
				"agent", single(r.Agents)),
			Evidence: []string{"case:" + r.ID.String()},
		})
	}
	return items, next, nil
}

func countCases(ctx context.Context, _ *Service, c tenancy.Caller, tx db.TenantTx, sc Scope, f Filters) (int, error) {
	n, err := dbq.New(tx).CountCases(ctx, dbq.CountCasesParams{
		OrgID: c.Org, AllAgents: sc.All, Agents: sc.agentList(), ID: f.ID, AgentID: f.Agent, AlertID: f.Alert,
		IncidentID: f.Incident, States: list(f.States), StartTime: f.Start, EndTime: f.End,
	})
	return int(n), err
}

func pageFindings(ctx context.Context, _ *Service, c tenancy.Caller, tx db.TenantTx, sc Scope, f Filters, pr page.Request) ([]Item, string, error) {
	rows, err := dbq.New(tx).SearchFindings(ctx, dbq.SearchFindingsParams{
		OrgID: c.Org, AllAgents: sc.All, Agents: sc.agentList(), Before: before(pr), ID: f.ID, AgentID: f.Agent,
		ConnectionID: f.Connection, GrantID: f.Grant, States: list(f.States), Kinds: list(f.Kinds),
		Severities: list(f.Severities), StartTime: f.Start, EndTime: f.End, PageLimit: pr.Limit(),
	})
	if err != nil {
		return nil, "", err
	}
	rows, next := page.Finish(pr, rows, func(r dbq.SearchFindingsRow) ids.UUID { return r.ID })
	items := make([]Item, 0, len(rows))
	for _, r := range rows {
		items = append(items, Item{
			Entity: EntityFindings, ID: r.ID.String(), Time: r.FirstSeenAt, Label: r.State,
			Fields: fields("title", r.Title, "kind", r.Kind, "root_cause", r.RootCause, "agent", idStr(r.AgentID),
				"connection", idStr(r.ConnectionID), "grant", idStr(r.GrantID), "severity", strings.ToUpper(r.Severity),
				"state", r.State, "owner", idStr(r.OwnerUserID), "last_seen", ts(&r.LastSeenAt)),
			Evidence: []string{"finding:" + r.ID.String()},
		})
	}
	return items, next, nil
}

func countFindings(ctx context.Context, _ *Service, c tenancy.Caller, tx db.TenantTx, sc Scope, f Filters) (int, error) {
	n, err := dbq.New(tx).CountFindings(ctx, dbq.CountFindingsParams{
		OrgID: c.Org, AllAgents: sc.All, Agents: sc.agentList(), ID: f.ID, AgentID: f.Agent, ConnectionID: f.Connection,
		GrantID: f.Grant, States: list(f.States), Kinds: list(f.Kinds), Severities: list(f.Severities),
		StartTime: f.Start, EndTime: f.End,
	})
	return int(n), err
}

func pagePolicyVersions(ctx context.Context, _ *Service, c tenancy.Caller, tx db.TenantTx, _ Scope, f Filters, pr page.Request) ([]Item, string, error) {
	rows, err := dbq.New(tx).SearchPolicyVersions(ctx, dbq.SearchPolicyVersionsParams{
		OrgID: c.Org, Before: before(pr), ID: f.ID, States: list(f.States), StartTime: f.Start, EndTime: f.End,
		PageLimit: pr.Limit(),
	})
	if err != nil {
		return nil, "", err
	}
	rows, next := page.Finish(pr, rows, func(r dbq.SearchPolicyVersionsRow) ids.UUID { return r.ID })
	items := make([]Item, 0, len(rows))
	for _, r := range rows {
		items = append(items, Item{
			Entity: EntityPolicyVersions, ID: r.ID.String(), Time: r.CreatedAt, Label: r.State,
			Fields: fields("policy", r.PolicyID.String(), "bundle", r.BundleID, "version", strconv.Itoa(int(r.Version)),
				"state", r.State, "created_by", r.CreatedBy, "published_by", str(r.PublishedBy), "published_at", ts(r.PublishedAt)),
			Evidence: []string{"policy_version:" + r.ID.String()},
		})
	}
	return items, next, nil
}

func countPolicyVersions(ctx context.Context, _ *Service, c tenancy.Caller, tx db.TenantTx, _ Scope, f Filters) (int, error) {
	n, err := dbq.New(tx).CountPolicyVersions(ctx, dbq.CountPolicyVersionsParams{
		OrgID: c.Org, ID: f.ID, States: list(f.States), StartTime: f.Start, EndTime: f.End,
	})
	return int(n), err
}

func pagePackages(ctx context.Context, _ *Service, c tenancy.Caller, tx db.TenantTx, _ Scope, f Filters, pr page.Request) ([]Item, string, error) {
	rows, err := dbq.New(tx).SearchPackages(ctx, dbq.SearchPackagesParams{
		OrgID: c.Org, Before: before(pr), ID: f.ID, States: list(f.States), StartTime: f.Start, EndTime: f.End,
		PageLimit: pr.Limit(),
	})
	if err != nil {
		return nil, "", err
	}
	rows, next := page.Finish(pr, rows, func(r dbq.SearchPackagesRow) ids.UUID { return r.ID })
	items := make([]Item, 0, len(rows))
	for _, r := range rows {
		items = append(items, Item{
			Entity: EntityPackages, ID: r.ID.String(), Time: r.CreatedAt, Label: r.LatestState,
			Fields: fields("name", r.Name, "latest_version", r.LatestVersion, "latest_state", r.LatestState,
				"latest_digest", r.LatestDigest),
			Evidence: []string{"package:" + r.ID.String()},
		})
	}
	return items, next, nil
}

func countPackages(ctx context.Context, _ *Service, c tenancy.Caller, tx db.TenantTx, _ Scope, f Filters) (int, error) {
	n, err := dbq.New(tx).CountPackages(ctx, dbq.CountPackagesParams{
		OrgID: c.Org, ID: f.ID, States: list(f.States), StartTime: f.Start, EndTime: f.End,
	})
	return int(n), err
}

func pageGateways(ctx context.Context, _ *Service, c tenancy.Caller, tx db.TenantTx, _ Scope, f Filters, pr page.Request) ([]Item, string, error) {
	rows, err := dbq.New(tx).SearchGateways(ctx, dbq.SearchGatewaysParams{
		OrgID: c.Org, Before: before(pr), ID: f.ID, States: list(f.States), StartTime: f.Start, EndTime: f.End,
		PageLimit: pr.Limit(),
	})
	if err != nil {
		return nil, "", err
	}
	rows, next := page.Finish(pr, rows, func(r dbq.SearchGatewaysRow) ids.UUID { return r.ID })
	items := make([]Item, 0, len(rows))
	for _, r := range rows {
		items = append(items, Item{
			Entity: EntityGateways, ID: r.ID.String(), Time: r.CreatedAt, Label: r.State,
			Fields: fields("name", r.Name, "state", r.State, "config_version", strconv.FormatInt(r.ConfigVersion, 10),
				"created_by", r.CreatedBy, "revoked_at", ts(r.RevokedAt)),
			Evidence: []string{"gateway:" + r.ID.String()},
		})
	}
	return items, next, nil
}

func countGateways(ctx context.Context, _ *Service, c tenancy.Caller, tx db.TenantTx, _ Scope, f Filters) (int, error) {
	n, err := dbq.New(tx).CountGateways(ctx, dbq.CountGatewaysParams{
		OrgID: c.Org, ID: f.ID, States: list(f.States), StartTime: f.Start, EndTime: f.End,
	})
	return int(n), err
}

func init() { runners[EntityAutomations] = runner{pageAutomations, countAutomations} }

func pageAutomations(ctx context.Context, _ *Service, c tenancy.Caller, tx db.TenantTx, _ Scope, f Filters, pr page.Request) ([]Item, string, error) {
	rows, err := dbq.New(tx).SearchAutomations(ctx, dbq.SearchAutomationsParams{
		OrgID: c.Org, Before: before(pr), ID: f.ID, States: list(f.States), Kinds: list(f.Kinds),
		StartTime: f.Start, EndTime: f.End, PageLimit: pr.Limit(),
	})
	if err != nil {
		return nil, "", err
	}
	rows, next := page.Finish(pr, rows, func(r dbq.SearchAutomationsRow) ids.UUID { return r.ID })
	// An automation's identity is a service account: shown only with
	// service_account.read across the org (D86 Q5).
	saRead := c.Can(td.PermServiceAccountRead, td.OrgPath(c.Org))
	items := make([]Item, 0, len(rows))
	for _, r := range rows {
		it := Item{
			Entity: EntityAutomations, ID: r.ID.String(), Time: r.CreatedAt, Label: r.State,
			Fields: fields("name", r.Name, "kind", r.Kind, "state", r.State, "rollout", str(r.Rollout),
				"owner", r.OwnerUserID.String(), "enabled_version", idStr(r.EnabledVersionID), "pause_reason", str(r.PauseReason)),
			Evidence: []string{"automation:" + r.ID.String()},
		}
		if saRead {
			it.Fields["service_account"] = r.ServiceAccountID.String()
			it.Evidence = append(it.Evidence, "service_account:"+r.ServiceAccountID.String())
		}
		items = append(items, it)
	}
	return items, next, nil
}

func countAutomations(ctx context.Context, _ *Service, c tenancy.Caller, tx db.TenantTx, _ Scope, f Filters) (int, error) {
	n, err := dbq.New(tx).CountAutomations(ctx, dbq.CountAutomationsParams{
		OrgID: c.Org, ID: f.ID, States: list(f.States), Kinds: list(f.Kinds), StartTime: f.Start, EndTime: f.End,
	})
	return int(n), err
}

// single is the one agent a row is about, else "" (several are listed in
// "agents"), so a case opened from it knows its agent (D79 S6).
func single(agents []string) string {
	if len(agents) == 1 {
		return agents[0]
	}
	return ""
}

func init() { runners[EntityExecutions] = runner{pageExecutions, countExecutions} }

func pageExecutions(ctx context.Context, _ *Service, c tenancy.Caller, tx db.TenantTx, _ Scope, f Filters, pr page.Request) ([]Item, string, error) {
	rows, err := dbq.New(tx).SearchAutomationExecutions(ctx, dbq.SearchAutomationExecutionsParams{
		OrgID: c.Org, Before: before(pr), ID: f.ID, AutomationID: f.Automation, States: list(f.States), Modes: list(f.Modes),
		Kinds: list(f.Kinds), StartTime: f.Start, EndTime: f.End, PageLimit: pr.Limit(),
	})
	if err != nil {
		return nil, "", err
	}
	rows, next := page.Finish(pr, rows, func(r dbq.SearchAutomationExecutionsRow) ids.UUID { return r.ID })
	items := make([]Item, 0, len(rows))
	for _, r := range rows {
		items = append(items, Item{
			Entity: EntityExecutions, ID: r.ID.String(), Time: r.CreatedAt, Label: r.State,
			Fields: fields("automation", r.AutomationID.String(), "automation_name", r.AutomationName,
				"version", r.VersionID.String(), "mode", r.Mode, "state", r.State, "reason", str(r.Reason),
				"trigger_kind", r.TriggerKind, "depth", strconv.Itoa(int(r.Depth)),
				"principal_user", idStr(r.PrincipalUserID), "principal_service_account", idStr(r.PrincipalSaID),
				"started_at", ts(r.StartedAt), "ended_at", ts(r.EndedAt)),
			Evidence: []string{"automation_execution:" + r.ID.String(), "automation:" + r.AutomationID.String()},
		})
	}
	return items, next, nil
}

func countExecutions(ctx context.Context, _ *Service, c tenancy.Caller, tx db.TenantTx, _ Scope, f Filters) (int, error) {
	n, err := dbq.New(tx).CountAutomationExecutions(ctx, dbq.CountAutomationExecutionsParams{
		OrgID: c.Org, ID: f.ID, AutomationID: f.Automation, States: list(f.States), Modes: list(f.Modes),
		Kinds: list(f.Kinds), StartTime: f.Start, EndTime: f.End,
	})
	return int(n), err
}
