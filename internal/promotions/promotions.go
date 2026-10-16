// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package promotions is the production promotion gate (G0 M11 part 2,
// coordinator decision D39; F333, F334, founder decision F6, HR-290,
// T-128). A promotion lets an agent receive new or widened grants for one
// operation (an exact name or a prefix such as payments.*) in one
// PRODUCTION environment. A person holding agent.promote makes it, with a
// fresh security-key step-up, and only for operations whose checks pass:
// OWNER (an active owner), IDENTITY (VERIFIED or later, with an admitted
// instance), TESTS (the published policy has a scenario test of it),
// APPROVALS (each approval requirement on it has an eligible approver),
// COVERAGE (every route ENFORCED or PARTIAL, not lapsed) and
// FAILURE_BEHAVIOR (declared). Readiness is always per operation.
//
// The Gate implements grants' PromotionGate: in a PRODUCTION environment a
// grant must list its operations, and each must be covered by an ACTIVE
// promotion. Existing grants are untouched (F6).
package promotions

import (
	"context"
	"encoding/json/v2"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"

	aapp "github.com/katocxl/pantherclaw/internal/agents/app"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
)

// Permissions. agent.promote is human only (D12); reads need agent.read
// where the agent lives.
const (
	PermPromote = td.PermAgentPromote
	PermRead    = td.PermAgentRead
)

// States of a promotion.
const (
	StateActive  = "ACTIVE"
	StateRevoked = "REVOKED"
)

const production = "PRODUCTION"

// Errors.
var (
	ErrNotFound       = pcerr.New(pcerr.NotFound, "PROMOTION_NOT_FOUND", "promotion not found")
	ErrAgentNotFound  = pcerr.New(pcerr.NotFound, "AGENT_NOT_FOUND", "agent not found")
	ErrHumanOnly      = pcerr.New(pcerr.PermissionDenied, "HUMAN_ONLY", "only a person signed in as themselves can promote an agent")
	ErrEnvironment    = pcerr.New(pcerr.FailedPrecondition, "ENVIRONMENT_MISMATCH", "the agent works in another environment")
	ErrNotProduction  = pcerr.New(pcerr.FailedPrecondition, "NOT_PRODUCTION", "promotions are for PRODUCTION environments only")
	ErrState          = pcerr.New(pcerr.FailedPrecondition, "PROMOTION_REVOKED", "the promotion is already revoked")
	ErrCompromised    = pcerr.New(pcerr.PermissionDenied, "PUBLISHER_COMPROMISED", "you are marked compromised and cannot promote")
	errFailureBehavor = pcerr.New(pcerr.InvalidArgument, "INVALID_FAILURE_BEHAVIOR", "declare FAIL_CLOSED, QUEUE or DEGRADE_READ_ONLY")
	errReason         = pcerr.New(pcerr.InvalidArgument, "INVALID_REASON", "give a reason of 1 to 500 characters")
)

func invalidOps(err error) error {
	return pcerr.Wrap(err, pcerr.InvalidArgument, "INVALID_OPERATIONS", err.Error())
}

// CompromiseChecker reports whether a person is marked compromised (G0 M11
// part 2, D43); a compromised person cannot promote.
type CompromiseChecker interface {
	Compromised(ctx context.Context, tx db.TenantTx, org ids.OrgID, user ids.UUID) (bool, error)
}

// Service runs the promotion use cases.
type Service struct {
	Pool *db.Pool
	// Compromise, when set, refuses a compromised person (nil: none is).
	Compromise CompromiseChecker
}

// Promotion is one stored promotion.
type Promotion struct {
	dbq.PcAgentPromotion
	Checks []Check
}

func promotionOf(r dbq.PcAgentPromotion) Promotion {
	p := Promotion{PcAgentPromotion: r}
	_ = json.Unmarshal(r.Checks, &p.Checks) // written by this package; a damaged list reads empty
	return p
}

// Result is what PromoteAgent did per operation: the promotions made, the
// operations already promoted, and the readiness of each operation asked.
type Result struct {
	Promoted  []Promotion
	Already   []Promotion
	Readiness []Readiness
}

// PromoteInput asks to promote an agent for operations in an environment.
type PromoteInput struct {
	Agent, Environment ids.UUID
	Operations         []string
	FailureBehavior    string
}

func person(ctx context.Context) (tapp.Caller, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	if !c.Human() || c.Credential == tapp.CredAPIKey {
		return c, ErrHumanOnly
	}
	return c, nil
}

// freshStepUp checks the step-up the promotions page passes from its
// browser session (siem/stepup, D53): a person, their own ACTIVE key, at
// most 5 minutes old by the database clock. It returns the key. Without
// one (every API call) it refuses STEP_UP_REQUIRED.
func freshStepUp(ctx context.Context, tx db.TenantTx, c tapp.Caller, su *stepup.StepUp) (ids.UUID, error) {
	if su == nil {
		return ids.UUID{}, stepup.ErrStepUp
	}
	now, err := dbq.New(tx).DBNow(ctx)
	if err != nil {
		return ids.UUID{}, err
	}
	if err := stepup.Check(ctx, tx, c, *su, now); err != nil {
		return ids.UUID{}, err
	}
	return su.Credential, nil
}

// agentAt reads an agent and checks p where it lives; an agent the caller
// cannot see is not found.
func agentAt(ctx context.Context, q *dbq.Queries, c tapp.Caller, id ids.UUID, p td.Permission) (dbq.PromotionSubjectRow, error) {
	a, err := q.GetAgent(ctx, c.Org, id)
	if db.IsNoRows(err) {
		return dbq.PromotionSubjectRow{}, ErrAgentNotFound
	} else if err != nil {
		return dbq.PromotionSubjectRow{}, err
	}
	path, err := aapp.PathOf(ctx, q, a)
	if err != nil {
		return dbq.PromotionSubjectRow{}, err
	}
	if !c.Can(PermRead, path) {
		return dbq.PromotionSubjectRow{}, ErrAgentNotFound
	}
	if err := c.Require(p, path); err != nil {
		return dbq.PromotionSubjectRow{}, err
	}
	return q.PromotionSubject(ctx, c.Org, id)
}

// PromoteAgent promotes an agent for each operation whose checks pass, in
// the agent's own PRODUCTION environment (agent.promote, human, and the
// fresh step-up su the promotions page passes from its session, D53; nil
// refuses STEP_UP_REQUIRED). Operations that fail a check are reported,
// not promoted; an operation already promoted is reported as such.
func (s *Service) PromoteAgent(ctx context.Context, in PromoteInput, su *stepup.StepUp) (Result, error) {
	c, err := person(ctx)
	if err != nil {
		return Result{}, err
	}
	ops, err := normalizeOperations(in.Operations)
	if err != nil {
		return Result{}, invalidOps(err)
	}
	if !slices.Contains(FailureBehaviors, in.FailureBehavior) {
		return Result{}, errFailureBehavor
	}
	var out Result
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		row, err := agentAt(ctx, q, c, in.Agent, PermPromote)
		if err != nil {
			return err
		}
		if row.EnvironmentID == nil || *row.EnvironmentID != in.Environment {
			return ErrEnvironment
		}
		if row.EnvironmentKind != production {
			return ErrNotProduction
		}
		cred, err := freshStepUp(ctx, tx, c, su)
		if err != nil {
			return err
		}
		if s.Compromise != nil {
			bad, err := s.Compromise.Compromised(ctx, tx, c.Org, c.Principal.ID)
			if err != nil {
				return err
			}
			if bad {
				return ErrCompromised
			}
		}
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		sub, err := load(ctx, q, c.Org, row, in.Environment)
		if err != nil {
			return err
		}
		if out.Readiness, err = sub.evaluate(ctx, q, ops, in.FailureBehavior, now); err != nil {
			return err
		}
		for i, r := range out.Readiness {
			cur, err := q.ActiveAgentPromotion(ctx, dbq.ActiveAgentPromotionParams{
				OrgID: c.Org, AgentID: in.Agent, EnvironmentID: in.Environment, Operation: r.Operation,
			})
			switch {
			case err == nil:
				p := promotionOf(cur)
				out.Readiness[i].Promotion, out.Already = &p, append(out.Already, p)
				continue
			case !db.IsNoRows(err):
				return err
			}
			if !r.Ready() {
				continue
			}
			checks, err := json.Marshal(r.Checks)
			if err != nil {
				return err
			}
			ins, err := q.InsertAgentPromotion(ctx, dbq.InsertAgentPromotionParams{
				OrgID: c.Org, ID: ids.NewV7(), AgentID: in.Agent, EnvironmentID: in.Environment, Operation: r.Operation,
				Checks: checks, FailureBehavior: in.FailureBehavior, PromotedBy: c.Principal.ID, CredentialID: cred,
			})
			if err != nil {
				return err
			}
			p := promotionOf(ins)
			out.Readiness[i].Promotion, out.Promoted = &p, append(out.Promoted, p)
			if _, err := audit.Record(ctx, tx, audit.Event{
				Name: "agent.promoted", Actor: c.Actor(), Outcome: audit.Success,
				Object: &audit.Object{Type: "agent", ID: in.Agent.String()},
				Details: map[string]string{
					"promotion": ins.ID.String(), "environment": in.Environment.String(), "operation": r.Operation,
					"failure_behavior": in.FailureBehavior, "security_key": cred.String(),
				},
			}); err != nil {
				return err
			}
		}
		return nil
	})
	return out, err
}

// RevokePromotion revokes an ACTIVE promotion (agent.promote, human). New
// and widened grants for the operation are refused from now on; existing
// grants keep working until they expire (F6).
func (s *Service) RevokePromotion(ctx context.Context, id ids.UUID, reason string) (Promotion, error) {
	c, err := person(ctx)
	if err != nil {
		return Promotion{}, err
	}
	if reason = strings.TrimSpace(reason); reason == "" || utf8.RuneCountInString(reason) > maxRevokeReason {
		return Promotion{}, errReason
	}
	var out Promotion
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		cur, err := q.GetAgentPromotion(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if _, err := agentAt(ctx, q, c, cur.AgentID, PermPromote); err != nil {
			if pcerr.CodeOf(err) == pcerr.NotFound {
				return ErrNotFound
			}
			return err
		}
		row, err := q.RevokeAgentPromotion(ctx, dbq.RevokeAgentPromotionParams{OrgID: c.Org, ID: id, RevokedBy: &c.Principal.ID, Reason: &reason})
		if db.IsNoRows(err) {
			return ErrState
		} else if err != nil {
			return err
		}
		out = promotionOf(row)
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: "agent.promotion_revoked", Actor: c.Actor(), Outcome: audit.Success,
			Object: &audit.Object{Type: "agent", ID: row.AgentID.String()},
			Details: map[string]string{
				"promotion": id.String(), "environment": row.EnvironmentID.String(), "operation": row.Operation, "reason": reason,
			},
		})
		return err
	})
	return out, err
}

// GetReadiness states each operation's readiness for an agent in an
// environment (agent.read). Without operations it reads those of the
// agent's ACTIVE promotions, its active grants' bounds and its coverage
// records there. failureBehavior, when given, is the behavior the
// failure-behavior check considers declared.
func (s *Service) GetReadiness(ctx context.Context, agent, env ids.UUID, operations []string, failureBehavior string) ([]Readiness, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return nil, err
	}
	var ops []string
	if len(operations) > 0 {
		if ops, err = normalizeOperations(operations); err != nil {
			return nil, invalidOps(err)
		}
	}
	if failureBehavior != "" && !slices.Contains(FailureBehaviors, failureBehavior) {
		return nil, errFailureBehavor
	}
	var out []Readiness
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		row, err := agentAt(ctx, q, c, agent, PermRead)
		if err != nil {
			return err
		}
		if row.EnvironmentID == nil || *row.EnvironmentID != env {
			return ErrEnvironment
		}
		sub, err := load(ctx, q, c.Org, row, env)
		if err != nil {
			return err
		}
		active, err := q.ListAgentPromotions(ctx, dbq.ListAgentPromotionsParams{
			OrgID: c.Org, AgentID: &agent, EnvironmentID: &env, State: ptr(StateActive), MaxRows: maxOperations * 4,
		})
		if err != nil {
			return err
		}
		if ops == nil {
			if ops, err = knownOperations(ctx, q, c.Org, agent, env, active, sub); err != nil {
				return err
			}
		}
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		if out, err = sub.evaluate(ctx, q, ops, failureBehavior, now); err != nil {
			return err
		}
		for i := range out {
			for _, a := range active {
				if a.Operation == out[i].Operation {
					p := promotionOf(a)
					out[i].Promotion = &p
					if failureBehavior == "" {
						out[i].Checks[len(out[i].Checks)-1] = declared(a.FailureBehavior)
					}
				}
			}
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// knownOperations are the operations an agent's promotions, active grants
// and coverage records name in the environment, sorted, at most
// maxOperations.
func knownOperations(ctx context.Context, q *dbq.Queries, org ids.OrgID, agent, env ids.UUID, active []dbq.PcAgentPromotion,
	sub *subject,
) ([]string, error) {
	var ops []string
	for _, a := range active {
		ops = append(ops, a.Operation)
	}
	bounds, err := q.AgentGrantBounds(ctx, org, agent, env)
	if err != nil {
		return nil, err
	}
	for _, raw := range bounds {
		var b gdomain.Bounds
		if json.Unmarshal(raw, &b) == nil && b.Operations != nil {
			ops = append(ops, *b.Operations...)
		}
	}
	for _, s := range sub.snapshots {
		ops = append(ops, s.Operation)
	}
	slices.Sort(ops)
	ops = slices.Compact(ops)
	if len(ops) > maxOperations {
		ops = ops[:maxOperations]
	}
	return ops, nil
}

// Filter narrows ListPromotions.
type Filter struct {
	Agent, Environment *ids.UUID
	// State is ACTIVE, REVOKED or "" for both.
	State string
}

const maxList = 200

// ListPromotions lists promotions, newest first, of the agents the caller
// may read (agent.read).
func (s *Service) ListPromotions(ctx context.Context, f Filter, after *ids.UUID, limit int) ([]Promotion, *ids.UUID, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return nil, nil, err
	}
	if limit <= 0 || limit > maxList {
		limit = maxList
	}
	var state *string
	if f.State != "" {
		state = &f.State
	}
	var out []Promotion
	var next *ids.UUID
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		rows, err := q.ListAgentPromotions(ctx, dbq.ListAgentPromotionsParams{
			OrgID: c.Org, AgentID: f.Agent, EnvironmentID: f.Environment, State: state, After: after, MaxRows: int32(limit + 1), //nolint:gosec // ≤ 201
		})
		if err != nil {
			return err
		}
		if len(rows) > limit {
			rows = rows[:limit]
			id := rows[limit-1].ID
			next = &id
		}
		seen := map[ids.UUID]bool{}
		for _, r := range rows {
			ok, known := seen[r.AgentID]
			if !known {
				a, err := q.GetAgent(ctx, c.Org, r.AgentID)
				if err != nil {
					return err
				}
				path, err := aapp.PathOf(ctx, q, a)
				if err != nil {
					return err
				}
				ok = c.Can(PermRead, path)
				seen[r.AgentID] = ok
			}
			if ok {
				out = append(out, promotionOf(r))
			}
		}
		return nil
	}, db.ReadOnly())
	return out, next, err
}

func ptr[T any](v T) *T { return &v }
