// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package triggers

import (
	"context"
	"fmt"
	"math"
	"slices"
	"strconv"
	"time"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// Condition probes (D19): the closed list of states a condition trigger
// may watch, and the fields each subject offers to `where` and to
// parameters (as text).
//
//	grant.expiring    an ACTIVE grant expiring within 7 days: grant, agent,
//	                  principal, task_ref, hours_left
//	approval.waiting  a pending approval request: request, kind, operation,
//	                  agent, run, minutes_waiting
//	coverage.below    an agent × connection × operation not ENFORCED (or
//	                  past its enforcement): agent, connection, operation,
//	                  state, since, minutes_since
//	run.long_running  an ACTIVE run: run, agent, minutes_active
//	agent.unclaimed   a DISCOVERED agent nobody claimed: agent,
//	                  days_discovered
const (
	ProbeGrantExpiring  = "grant.expiring"
	ProbeApprovalWait   = "approval.waiting"
	ProbeCoverageBelow  = "coverage.below"
	ProbeRunLongRunning = "run.long_running"
	ProbeAgentUnclaimed = "agent.unclaimed"
)

var probes = []string{ProbeGrantExpiring, ProbeApprovalWait, ProbeCoverageBelow, ProbeRunLongRunning, ProbeAgentUnclaimed}

// Probes lists the probe names.
func Probes() []string { return slices.Clone(probes) }

// KnownProbe reports whether name is a probe.
func KnownProbe(name string) bool { return slices.Contains(probes, name) }

// Probe bounds (D19).
const (
	// MaxProbeSubjects is the most subjects one probe yields per
	// evaluation; more is an owned failure (automation.probe_overflow).
	MaxProbeSubjects = 1000
	// grantHorizon is how far ahead grant.expiring looks.
	grantHorizon = 7 * 24 * time.Hour
	// ConditionInterval is how often conditions are evaluated.
	ConditionInterval = time.Minute
)

// ProbeSubject is one subject a probe yields.
type ProbeSubject struct {
	Probe  string
	Key    string
	Fields map[string]string
	// Subjects are the platform subjects it names; Execution is the
	// automation execution behind it, if any (its ancestry is inherited,
	// D58).
	Subjects  []reflexdomain.Subject
	Execution *ids.UUID
}

// probeResult is one probe's subjects, or overflow.
type probeResult struct {
	subjects []ProbeSubject
	overflow bool
}

func uuidText(u *ids.UUID) string {
	if u == nil || u.IsZero() {
		return ""
	}
	return u.String()
}

// RunProbe reads one probe's subjects at now.
func RunProbe(ctx context.Context, q *dbq.Queries, org ids.OrgID, probe string, now time.Time) ([]ProbeSubject, bool, error) {
	const limit = MaxProbeSubjects + 1
	var out []ProbeSubject
	switch probe {
	case ProbeGrantExpiring:
		rows, err := q.ProbeGrantsExpiring(ctx, org, now.Add(grantHorizon), limit)
		if err != nil {
			return nil, false, err
		}
		for _, r := range rows {
			principal := "user:" + uuidText(r.PrincipalUserID)
			if r.PrincipalSaID != nil {
				principal = "service_account:" + uuidText(r.PrincipalSaID)
			}
			out = append(out, ProbeSubject{
				Probe: probe, Key: "grant:" + r.ID.String(),
				Fields: map[string]string{
					"grant": r.ID.String(), "agent": r.AgentID.String(), "principal": principal, "task_ref": r.TaskRef,
					"hours_left": strconv.Itoa(int(math.Floor(r.ExpiresAt.Sub(now).Hours()))),
				},
				Subjects: []reflexdomain.Subject{
					{Type: reflexdomain.SubjectGrant, ID: r.ID.String()}, {Type: reflexdomain.SubjectAgent, ID: r.AgentID.String()},
				},
				Execution: r.AutomationExecutionID,
			})
		}
	case ProbeApprovalWait:
		rows, err := q.ProbeApprovalsWaiting(ctx, org, limit)
		if err != nil {
			return nil, false, err
		}
		for _, r := range rows {
			s := ProbeSubject{
				Probe: probe, Key: "approval_request:" + r.ID.String(),
				Fields: map[string]string{
					"request": r.ID.String(), "kind": r.SubjectKind, "operation": r.Operation, "agent": uuidText(r.AgentID),
					"run": uuidText(r.RunID), "minutes_waiting": strconv.Itoa(int(now.Sub(r.CreatedAt).Minutes())),
				},
				Execution: r.AutomationExecutionID,
			}
			// A gate request may have no agent (D25a).
			if r.AgentID != nil {
				s.Subjects = append(s.Subjects, reflexdomain.Subject{Type: reflexdomain.SubjectAgent, ID: r.AgentID.String()})
			}
			// A gate request descends from its own execution (D87 L6).
			if r.GateExecutionID != nil {
				s.Execution = r.GateExecutionID
			}
			if r.RunID != nil {
				s.Subjects = append(s.Subjects, reflexdomain.Subject{Type: reflexdomain.SubjectRun, ID: r.RunID.String()})
			}
			out = append(out, s)
		}
	case ProbeCoverageBelow:
		rows, err := q.ProbeCoverageBelow(ctx, org, limit)
		if err != nil {
			return nil, false, err
		}
		for _, r := range rows {
			state := r.State
			if state == "ENFORCED" {
				state = "EXPIRED"
			}
			out = append(out, ProbeSubject{
				Probe: probe, Key: "coverage:" + r.AgentID.String() + ":" + r.ConnectionID.String() + ":" + r.Operation,
				Fields: map[string]string{
					"agent": r.AgentID.String(), "connection": r.ConnectionID.String(), "operation": r.Operation,
					"state": state, "since": r.ComputedAt.UTC().Format(time.RFC3339),
					"minutes_since": strconv.Itoa(int(now.Sub(r.ComputedAt).Minutes())),
				},
				Subjects: []reflexdomain.Subject{
					{Type: reflexdomain.SubjectAgent, ID: r.AgentID.String()},
					{Type: reflexdomain.SubjectConnection, ID: r.ConnectionID.String()},
				},
			})
		}
	case ProbeRunLongRunning:
		rows, err := q.ProbeRunsLongRunning(ctx, org, limit)
		if err != nil {
			return nil, false, err
		}
		for _, r := range rows {
			out = append(out, ProbeSubject{
				Probe: probe, Key: "run:" + r.ID.String(),
				Fields: map[string]string{
					"run": r.ID.String(), "agent": r.AgentID.String(),
					"minutes_active": strconv.Itoa(int(now.Sub(r.CreatedAt).Minutes())),
				},
				Subjects: []reflexdomain.Subject{
					{Type: reflexdomain.SubjectRun, ID: r.ID.String()}, {Type: reflexdomain.SubjectAgent, ID: r.AgentID.String()},
				},
				Execution: r.AutomationExecutionID,
			})
		}
	case ProbeAgentUnclaimed:
		rows, err := q.ProbeAgentsUnclaimed(ctx, org, limit)
		if err != nil {
			return nil, false, err
		}
		for _, r := range rows {
			out = append(out, ProbeSubject{
				Probe: probe, Key: "agent:" + r.ID.String(),
				Fields: map[string]string{
					"agent": r.ID.String(), "days_discovered": strconv.Itoa(int(now.Sub(r.CreatedAt).Hours() / 24)),
				},
				Subjects: []reflexdomain.Subject{{Type: reflexdomain.SubjectAgent, ID: r.ID.String()}},
			})
		}
	default:
		return nil, false, fmt.Errorf("triggers: unknown probe %q", probe)
	}
	if len(out) > MaxProbeSubjects {
		return out[:MaxProbeSubjects], true, nil
	}
	return out, false, nil
}

// EvaluateConditions evaluates every condition trigger of org once (D19):
// a subject that matches `where` starts or continues its episode, an
// episode that has held for `for` fires once, and episodes whose subject
// no longer matches end.
func (s *Service) EvaluateConditions(ctx context.Context, org ids.OrgID) (fired int, err error) {
	if ok, err := s.licensed(ctx); !ok {
		return 0, err
	}
	err = s.d.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		fired = 0
		q := dbq.New(tx)
		rows, err := q.ActiveAutomationsWithTrigger(ctx, org, "condition")
		if err != nil || len(rows) == 0 {
			return err
		}
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		cache := map[string]probeResult{}
		for _, r := range rows {
			a, err := automationOf(r.ID, r.Name, r.State, r.Rollout, r.ServiceAccountID, r.OwnerUserID, r.VersionID, r.Definition)
			if err != nil {
				s.d.Log.WarnContext(ctx, "automations.condition_definition", "automation", r.ID.String())
				continue
			}
			cw := a.Def.When.Condition
			if cw == nil || !KnownProbe(cw.Probe) {
				continue
			}
			res, ok := cache[cw.Probe]
			if !ok {
				subs, overflow, err := RunProbe(ctx, q, org, cw.Probe, now)
				if err != nil {
					return err
				}
				res = probeResult{subjects: subs, overflow: overflow}
				cache[cw.Probe] = res
			}
			if res.overflow {
				if err := s.failure(ctx, tx, reflexdomain.Failure{
					Org: org, Kind: FailureProbeOverflow,
					DedupeKey: FailureProbeOverflow + ":" + a.ID.String() + ":" + now.UTC().Format("2006-01-02T15"),
					Summary: fmt.Sprintf("Probe %s of automation %s found more than %d subjects; only the first %d were evaluated.",
						cw.Probe, a.Name, MaxProbeSubjects, MaxProbeSubjects),
					NextStep: "Narrow the condition, or resolve the subjects it finds.",
					Scope:    []reflexdomain.Subject{{Type: reflexdomain.SubjectAutomation, ID: a.ID.String()}},
					Owner:    &reflexdomain.Subject{Type: reflexdomain.SubjectUser, ID: a.Owner.String()},
				}); err != nil {
					return err
				}
			}
			n, err := s.evaluateCondition(ctx, tx, a, cw, res.subjects, now)
			if err != nil {
				return err
			}
			fired += n
		}
		return nil
	})
	return fired, err
}

func (s *Service) evaluateCondition(ctx context.Context, tx db.TenantTx, a Automation, cw *autodomain.ConditionWhen,
	subs []ProbeSubject, now time.Time,
) (int, error) {
	q := dbq.New(tx)
	org := tx.OrgID()
	fired := 0
	for _, sub := range subs {
		ok, err := MatchSubject(ctx, cw.Where, sub)
		if err != nil || !ok {
			continue
		}
		ep, err := q.UpsertConditionEpisode(ctx, dbq.UpsertConditionEpisodeParams{
			OrgID: org, AutomationID: a.ID, SubjectKey: truncate(sub.Key, 300), Now: now,
		})
		if err != nil {
			return fired, err
		}
		if ep.FiredAt != nil || now.Sub(ep.Since) < cw.For.D() {
			continue
		}
		if _, err := q.MarkConditionFired(ctx, dbq.MarkConditionFiredParams{
			Now: &now, OrgID: org, AutomationID: a.ID, SubjectKey: truncate(sub.Key, 300),
		}); err != nil {
			return fired, err
		}
		lin, err := s.lineageOfExecution(ctx, q, org, sub.Execution)
		if err != nil {
			return fired, err
		}
		fields := sub.Fields
		params, perr := ExtractFields(cw.Params, func(p string) (string, bool) {
			v, ok := fields[p]
			return v, ok && v != ""
		})
		out, ok := s.FireInSavepoint(ctx, tx, Candidate{
			Automation: a, Kind: autodomain.TriggerCondition, Authenticity: autodomain.AuthPlatformFeed,
			Detail:    map[string]string{"probe": cw.Probe, "subject": truncate(sub.Key, 300), "since": ep.Since.UTC().Format(time.RFC3339)},
			SourceRef: "probe:" + cw.Probe + ":" + sub.Key, Params: params, ParamErr: perr, Subjects: sub.Subjects,
			Lineage: lin, BaseKey: ConditionKey(a.ID, sub.Key, ep.Since), OccurredAt: now, QueueOK: true,
		})
		if ok && out.State.Started() {
			fired++
		}
	}
	_, err := q.EndConditionEpisodes(ctx, org, a.ID, now)
	return fired, err
}

// lineageOfExecution is the lineage a subject behind an automation
// execution inherits (D23, D58); zero when there is none.
func (s *Service) lineageOfExecution(ctx context.Context, q *dbq.Queries, org ids.OrgID, exec *ids.UUID) (Lineage, error) {
	if exec == nil || exec.IsZero() {
		return Lineage{}, nil
	}
	t, err := q.TriggerOfExecution(ctx, org, exec)
	if db.IsNoRows(err) {
		return Lineage{}, nil
	} else if err != nil {
		return Lineage{}, err
	}
	return Parent{Trigger: t.ID, Automation: t.AutomationID, Root: t.RootTriggerID, Ancestry: t.Ancestry, Depth: int(t.Depth)}.Child(), nil
}
