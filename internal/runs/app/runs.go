// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app holds the run use cases (Badge; PAP-1 §5, HR-022, HR-146,
// G0 M3 constraints 17 and 18). A run is minted here, never by a client,
// and bound to an agent, optionally one admitted instance, the launcher
// and the represented principal. The principal is the launcher itself or,
// for a child run, its parent's principal; a launcher can never name one.
// Since M4 a run started by a person or a service account may be bound to
// a root grant, which is then the only authority its actions can use
// (HR-022, PN-002.5); a child run gets one only by delegation.
package app

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"strconv"
	"time"
	"unicode/utf8"

	agents "github.com/katocxl/pantherclaw/internal/agents/app"
	adomain "github.com/katocxl/pantherclaw/internal/agents/domain"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Run limits (G0 M3 constraint 17).
const (
	DefaultTTL = 8 * time.Hour
	MaxTTL     = 24 * time.Hour
	MaxDepth   = 8
	MaxTaskRef = 256
	MaxReason  = 64
)

// Principal sources (HR-146).
const (
	SourceLauncher     = "launcher"
	SourceSubjectToken = "subject_token"
	SourceParentRun    = "parent_run"
	// SourceAutomation: the principal an automation version declares, which
	// a confirmer consented to (G0 M11 part 2 D10).
	SourceAutomation = "automation"
)

// Errors.
var (
	ErrRunNotFound   = pcerr.New(pcerr.NotFound, "RUN_NOT_FOUND", "run not found")
	ErrAgentNotFound = pcerr.New(pcerr.NotFound, "AGENT_NOT_FOUND", "agent not found")
	ErrAgentUnusable = pcerr.New(pcerr.FailedPrecondition, "AGENT_STATE",
		"the agent must be claimed and neither suspended nor retired")
	ErrInstance = pcerr.New(pcerr.FailedPrecondition, "INSTANCE_STATE",
		"the instance must be an admitted instance of the agent")
	ErrRunState = pcerr.New(pcerr.FailedPrecondition, "RUN_STATE", "the run is not active")
	ErrDepth    = pcerr.New(pcerr.FailedPrecondition, "RUN_DEPTH", "child runs nest at most 8 levels deep")
	ErrLauncher = pcerr.New(pcerr.PermissionDenied, "LAUNCHER_KIND", "runs are started by users and service accounts")
	ErrTaskRef  = pcerr.New(pcerr.InvalidArgument, "TASK_REF", "task_ref is at most 256 characters of valid UTF-8")
	ErrTTL      = pcerr.New(pcerr.InvalidArgument, "RUN_TTL", "a run lasts at most 24 hours")
	ErrReason   = pcerr.New(pcerr.InvalidArgument, "REASON", "the reason is 1 to 64 characters")
	// ErrSimulationMismatch: a simulated run starts only children of range agents (G0 M12, HR-220).
	ErrSimulationMismatch = pcerr.New(pcerr.FailedPrecondition, "SIMULATION_MISMATCH",
		"a simulated run starts only child runs of range agents")
	ErrGrantNotFound  = pcerr.New(pcerr.NotFound, "GRANT_NOT_FOUND", "grant not found")
	ErrGrantDelegated = pcerr.New(pcerr.FailedPrecondition, gdomain.ReasonGrantMismatch,
		"a delegated grant reaches its child run only through delegation")
	ErrGrantMismatch = pcerr.New(pcerr.FailedPrecondition, gdomain.ReasonGrantMismatch,
		"the grant is for another agent, instance, principal or environment")
	ErrGrantsUnavailable = pcerr.New(pcerr.FailedPrecondition, "GRANTS_UNAVAILABLE", "this server cannot bind grants to runs")
	// ErrSubjectToken is returned when no identity provider is configured
	// for subject tokens (auth.oidc_providers[].subject_token_audience).
	ErrSubjectToken = pcerr.New(pcerr.FailedPrecondition, "SUBJECT_TOKEN_UNAVAILABLE",
		"this server accepts no subject tokens")
	ErrSubjectType = pcerr.New(pcerr.InvalidArgument, "SUBJECT_TOKEN_TYPE",
		"subject_token_type is an ID token or an access token")
	ErrSubjectRejected = pcerr.New(pcerr.PermissionDenied, "SUBJECT_TOKEN",
		"the subject token was not accepted: it must be a fresh, unused token from a configured provider for an active user of this organization")
)

// Actor is one link of a run's actor chain (F027).
type Actor struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// Run is one run.
type Run struct {
	ID              ids.UUID
	AgentID         ids.UUID
	InstanceID      *ids.UUID
	EnvironmentID   ids.UUID
	Launcher        Actor
	Principal       Actor
	PrincipalSource string
	SubjectIssuer   string
	SubjectSubject  string
	ActorChain      []Actor
	ParentRunID     *ids.UUID
	Depth           int
	// GrantID is the grant whose authority the run uses (nil: none, so its
	// actions are denied NO_GRANT).
	GrantID *ids.UUID
	TaskRef string
	// Simulated runs belong to range agents or descend from one (HR-220);
	// fixed when the run starts.
	Simulated bool
	// State is the effective state: an active run past its expiry reads
	// EXPIRED.
	State     string
	EndReason string
	CreatedAt time.Time
	ExpiresAt time.Time
	EndedAt   *time.Time
}

func actorOf(user, sa, instance *ids.UUID) Actor {
	switch {
	case user != nil:
		return Actor{Kind: string(td.KindUser), ID: user.String()}
	case sa != nil:
		return Actor{Kind: string(td.KindServiceAccount), ID: sa.String()}
	case instance != nil:
		return Actor{Kind: "instance", ID: instance.String()}
	}
	return Actor{}
}

func view(r dbq.PcRun, state string) (Run, error) {
	out := Run{
		ID: r.ID, AgentID: r.AgentID, InstanceID: r.InstanceID, EnvironmentID: r.EnvironmentID,
		Launcher:        actorOf(r.LauncherUserID, r.LauncherSaID, r.LauncherInstanceID),
		Principal:       actorOf(r.PrincipalUserID, r.PrincipalSaID, nil),
		PrincipalSource: r.PrincipalSource, ParentRunID: r.ParentRunID, Depth: int(r.Depth), GrantID: r.GrantID, TaskRef: r.TaskRef,
		Simulated: r.Simulated, State: state, CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt, EndedAt: r.EndedAt,
	}
	if r.SubjectIssuer != nil {
		out.SubjectIssuer = *r.SubjectIssuer
	}
	if r.SubjectSubject != nil {
		out.SubjectSubject = *r.SubjectSubject
	}
	if r.EndReason != nil {
		out.EndReason = *r.EndReason
	}
	return out, json.Unmarshal(r.ActorChain, &out.ActorChain)
}

// Service serves the run use cases.
type Service struct {
	pool     *db.Pool
	clk      clock.Clock
	subjects SubjectVerifier
	grants   Grants
	// automationRuns counts automation runs against their daily cap.
	automationRuns AutomationRuns
}

// New returns the run use cases.
func New(pool *db.Pool) *Service { return &Service{pool: pool, clk: clock.System{}} }

// StartInput starts a run.
type StartInput struct {
	AgentID    ids.UUID
	InstanceID *ids.UUID
	// TaskRef is an UNTRUSTED label (HR-023).
	TaskRef string
	// TTL defaults to DefaultTTL.
	TTL              time.Duration
	SubjectToken     string
	SubjectTokenType string
	// GrantID, when set, binds the run to that root grant.
	GrantID *ids.UUID
}

func checkLabel(taskRef string, ttl time.Duration) (int32, error) {
	if utf8.RuneCountInString(taskRef) > MaxTaskRef || !utf8.ValidString(taskRef) {
		return 0, ErrTaskRef
	}
	if ttl < 0 || ttl > MaxTTL {
		return 0, ErrTTL
	}
	return int32(ttl / time.Minute), nil
}

// Subject token types (RFC 8693 subject_token_type).
const (
	SubjectIDToken     = "id_token"
	SubjectAccessToken = "access_token"
)

// SubjectVerifier verifies subject tokens with the configured identity
// providers (oidcrp.Subjects).
type SubjectVerifier interface {
	VerifySubject(ctx context.Context, raw string, accessToken bool, now time.Time) (authnapp.SubjectClaims, error)
}

// WithSubjects lets runs represent users proven by subject tokens; without
// it every subject token is refused.
func (s *Service) WithSubjects(v SubjectVerifier) *Service {
	s.subjects = v
	return s
}

// launchable loads the agent a caller may start a run of: usable, with
// run.start (and run.represent for a subject token) where it lives, and
// the instance, when given, one of its admitted instances.
func launchable(ctx context.Context, c tenancy.Caller, q *dbq.Queries, in StartInput) (dbq.PcAgent, error) {
	a, err := usableAgent(ctx, q, c.Org, in.AgentID)
	if err != nil {
		return a, err
	}
	path, err := agents.PathOf(ctx, q, a)
	if err != nil {
		return a, err
	}
	if err := c.Require(td.PermRunStart, path); err != nil {
		return a, err
	}
	if in.SubjectToken != "" {
		if err := c.Require(td.PermRunRepresent, path); err != nil {
			return a, err
		}
	}
	if in.InstanceID != nil {
		return a, admittedInstance(ctx, q, c.Org, a.ID, *in.InstanceID)
	}
	return a, nil
}

// StartRun starts a run (HR-146). Its principal is the launcher, or the
// user a subject token proves (HR-145): presenting one needs run.represent,
// the token is verified with the configured provider and accepted once,
// and its (iss, sub) must be an active user of the org. The token grants
// nothing: the run's only authority is the grant in.GrantID names, checked
// against the run's agent, instance, principal and environment. The
// agent must be usable and the instance, when given, one of its admitted
// instances; without one, the run binds to the first admitted instance
// that uses it.
func (s *Service) StartRun(ctx context.Context, in StartInput) (Run, error) {
	if in.TTL == 0 {
		in.TTL = DefaultTTL
	}
	minutes, err := checkLabel(in.TaskRef, in.TTL)
	if err != nil {
		return Run{}, err
	}
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Run{}, err
	}
	if c.Principal.Kind != td.KindUser && c.Principal.Kind != td.KindServiceAccount {
		return Run{}, ErrLauncher
	}
	var subject *authnapp.SubjectClaims
	if in.SubjectToken != "" {
		if s.subjects == nil {
			return Run{}, ErrSubjectToken
		}
		if in.SubjectTokenType != SubjectIDToken && in.SubjectTokenType != SubjectAccessToken {
			return Run{}, ErrSubjectType
		}
		// The launcher's permissions are checked before the token is
		// verified or consumed.
		if err := s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := launchable(ctx, c, dbq.New(tx), in)
			return err
		}); err != nil {
			return Run{}, err
		}
		sc, err := s.subjects.VerifySubject(ctx, in.SubjectToken, in.SubjectTokenType == SubjectAccessToken, s.clk.Now())
		if err != nil {
			return Run{}, pcerr.Wrap(err, pcerr.PermissionDenied, ErrSubjectRejected.Reason(), ErrSubjectRejected.Message())
		}
		subject = &sc
	}
	var out Run
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		a, err := launchable(ctx, c, q, in)
		if err != nil {
			return err
		}
		launcher := Actor{Kind: string(c.Principal.Kind), ID: c.Principal.ID.String()}
		chain := []Actor{launcher}
		p := dbq.InsertRunParams{
			OrgID: c.Org, ID: ids.NewV7(), AgentID: a.ID, InstanceID: in.InstanceID, EnvironmentID: *a.EnvironmentID,
			PrincipalSource: SourceLauncher, TaskRef: in.TaskRef, TtlMinutes: minutes, Simulated: a.RangeAgent,
		}
		id := c.Principal.ID
		if c.Principal.Kind == td.KindUser {
			p.LauncherUserID, p.PrincipalUserID = &id, &id
		} else {
			p.LauncherSaID, p.PrincipalSaID = &id, &id
		}
		if subject != nil {
			user, err := represented(ctx, q, c.Org, *subject, in.SubjectToken)
			if err != nil {
				return err
			}
			p.PrincipalUserID, p.PrincipalSaID, p.PrincipalSource = &user, nil, SourceSubjectToken
			p.SubjectIssuer, p.SubjectSubject = &subject.Issuer, &subject.Subject
			chain = []Actor{{Kind: string(td.KindUser), ID: user.String()}, launcher}
		}
		if p.ActorChain, err = json.Marshal(chain); err != nil {
			return err
		}
		if in.GrantID != nil {
			if err := s.bindGrant(ctx, tx, c.Org, *in.GrantID, &p); err != nil {
				return err
			}
		}
		r, err := q.InsertRun(ctx, p)
		if err != nil {
			return err
		}
		if out, err = view(r, r.State); err != nil {
			return err
		}
		return record(ctx, tx, c.Actor(), "run.started", out)
	})
	return out, err
}

// represented returns the active user a verified subject token proves and
// consumes the token (HR-145): auth_replay keeps hashes of the issuer and
// of the jti (or of the token) until the token expires.
func represented(ctx context.Context, q *dbq.Queries, org ids.OrgID, sc authnapp.SubjectClaims, token string) (ids.UUID, error) {
	user, err := q.ActiveUserBySubject(ctx, org, sc.Issuer, sc.Subject)
	if db.IsNoRows(err) {
		return user, ErrSubjectRejected
	} else if err != nil {
		return user, err
	}
	if c, ok := jws.Canonical(token); ok {
		token = c // one key for every encoding that verifies as this token
	}
	key := "tok:" + token
	if sc.JTI != "" {
		key = "jti:" + sc.JTI
	}
	iss, jti := sha256.Sum256([]byte(sc.Issuer)), sha256.Sum256([]byte(key))
	n, err := q.InsertAuthReplay(ctx, dbq.InsertAuthReplayParams{
		OrgID: org, Issuer: "subject:" + base64.RawURLEncoding.EncodeToString(iss[:]),
		Jti: base64.RawURLEncoding.EncodeToString(jti[:]), ExpiresAt: sc.ExpiresAt,
	})
	if err != nil {
		return user, err
	}
	if n == 0 {
		return user, ErrSubjectRejected
	}
	return user, nil
}

// ChildInput starts a child run for a workload.
type ChildInput struct {
	// Caller is the instance proven by the workload token and proof.
	Caller      pap.Instance
	ParentRunID ids.UUID
	AgentID     ids.UUID
	InstanceID  *ids.UUID
	TaskRef     string
	// TTL defaults to, and is capped at, the parent's remaining time.
	TTL time.Duration
}

// StartChildRun starts a child of the caller's active run (G0 M3
// constraint 17). The parent must be bound to the calling instance; the
// child inherits the parent's principal, records the instance as its
// launcher, nests at most MaxDepth deep and never outlives the parent. A
// parent the caller cannot use is run_mismatch, as on Authorize.
func (s *Service) StartChildRun(ctx context.Context, in ChildInput) (Run, error) {
	if in.TTL == 0 {
		in.TTL = MaxTTL
	}
	minutes, err := checkLabel(in.TaskRef, in.TTL)
	if err != nil {
		return Run{}, err
	}
	org := in.Caller.Org
	var out Run
	err = s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		inst, err := q.GetInstance(ctx, org, in.Caller.Instance)
		if err != nil || inst.State != "ADMITTED" || inst.AgentID != in.Caller.Agent {
			return pap.Err(pap.CodeInstanceNotAdmitted)
		}
		pr, err := q.LockRun(ctx, org, in.ParentRunID)
		parent := pr.PcRun
		if db.IsNoRows(err) || (err == nil && (pr.EffectiveState != "ACTIVE" || parent.AgentID != in.Caller.Agent ||
			parent.InstanceID == nil || *parent.InstanceID != in.Caller.Instance)) {
			return pap.Err(pap.CodeRunMismatch)
		} else if err != nil {
			return err
		}
		if parent.Depth >= MaxDepth {
			return ErrDepth
		}
		a, err := usableAgent(ctx, q, org, in.AgentID)
		if err != nil {
			return err
		}
		// HR-220: a simulated run never starts a child of a real agent; a
		// child of a range agent is simulated whatever its parent is.
		if parent.Simulated && !a.RangeAgent {
			return ErrSimulationMismatch
		}
		if in.InstanceID != nil {
			if err := admittedInstance(ctx, q, org, a.ID, *in.InstanceID); err != nil {
				return err
			}
		}
		var chain []Actor
		if err := json.Unmarshal(parent.ActorChain, &chain); err != nil {
			return err
		}
		chainJSON, err := json.Marshal(append(chain, Actor{Kind: "instance", ID: inst.ID.String()}))
		if err != nil {
			return err
		}
		r, err := q.InsertRun(ctx, dbq.InsertRunParams{
			OrgID: org, ID: ids.NewV7(), AgentID: a.ID, InstanceID: in.InstanceID, EnvironmentID: *a.EnvironmentID,
			LauncherInstanceID: &inst.ID, PrincipalUserID: parent.PrincipalUserID, PrincipalSaID: parent.PrincipalSaID,
			PrincipalSource: SourceParentRun, ActorChain: chainJSON, ParentRunID: &parent.ID, Depth: parent.Depth + 1,
			AutomationExecutionID: parent.AutomationExecutionID, // HR-274 attribution one level down (D91)
			TaskRef:               in.TaskRef, TtlMinutes: minutes, NotAfter: &parent.ExpiresAt,
			Simulated: parent.Simulated || a.RangeAgent,
		})
		if err != nil {
			return err
		}
		if out, err = view(r, r.State); err != nil {
			return err
		}
		return record(ctx, tx, evdomain.Actor{Type: "instance", ID: inst.ID.String()}, "run.started", out)
	})
	return out, err
}

// readable loads a run the caller may act on with p where its agent
// lives.
func readable(ctx context.Context, c tenancy.Caller, q *dbq.Queries, id ids.UUID, p td.Permission, lock bool) (dbq.PcRun, string, error) {
	var r dbq.PcRun
	var state string
	if lock {
		row, err := q.LockRun(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return r, "", ErrRunNotFound
		} else if err != nil {
			return r, "", err
		}
		r, state = row.PcRun, row.EffectiveState
	} else {
		row, err := q.GetRun(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return r, "", ErrRunNotFound
		} else if err != nil {
			return r, "", err
		}
		r, state = row.PcRun, row.EffectiveState
	}
	a, err := q.GetAgent(ctx, c.Org, r.AgentID)
	if err != nil {
		return r, "", err
	}
	path, err := agents.PathOf(ctx, q, a)
	if err != nil {
		return r, "", err
	}
	return r, state, c.Require(p, path)
}

// GetRun returns one run (run.read where its agent lives).
func (s *Service) GetRun(ctx context.Context, id ids.UUID) (Run, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Run{}, err
	}
	var out Run
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		r, state, err := readable(ctx, c, dbq.New(tx), id, td.PermRunRead, false)
		if err != nil {
			return err
		}
		out, err = view(r, state)
		return err
	}, db.ReadOnly())
	return out, err
}

// Page is one page of runs.
type Page struct {
	Items []Run
	Next  string
}

// ListRuns lists the runs the caller may read, oldest first.
func (s *Service) ListRuns(ctx context.Context, pr page.Request, agent *ids.UUID, states []string) (Page, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Page{}, err
	}
	if states == nil {
		states = []string{}
	}
	var out Page
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		rows, err := q.ListRuns(ctx, dbq.ListRunsParams{
			OrgID: c.Org, After: pr.After, AgentID: agent, States: states, PageLimit: pr.Limit(),
		})
		if err != nil {
			return err
		}
		rows, out.Next = page.Finish(pr, rows, func(r dbq.ListRunsRow) ids.UUID { return r.PcRun.ID })
		allowed := map[ids.UUID]bool{}
		for _, row := range rows {
			ok, seen := allowed[row.PcRun.AgentID]
			if !seen {
				a, err := q.GetAgent(ctx, c.Org, row.PcRun.AgentID)
				if err != nil {
					return err
				}
				path, err := agents.PathOf(ctx, q, a)
				if err != nil {
					return err
				}
				ok = c.Can(td.PermRunRead, path)
				allowed[row.PcRun.AgentID] = ok
			}
			if !ok {
				continue
			}
			r, err := view(row.PcRun, row.EffectiveState)
			if err != nil {
				return err
			}
			out.Items = append(out.Items, r)
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// EndRun ends an active run (run.manage where its agent lives) and revokes
// its child runs in the same transaction.
func (s *Service) EndRun(ctx context.Context, id ids.UUID, reason string) (Run, error) {
	if reason == "" || utf8.RuneCountInString(reason) > MaxReason || !utf8.ValidString(reason) {
		return Run{}, ErrReason
	}
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Run{}, err
	}
	var out Run
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		_, state, err := readable(ctx, c, q, id, td.PermRunManage, true)
		if err != nil {
			return err
		}
		if state != "ACTIVE" {
			return ErrRunState
		}
		rows, err := q.EndRunTree(ctx, dbq.EndRunTreeParams{OrgID: c.Org, ID: id, State: "ENDED", Reason: reason})
		if err != nil {
			return err
		}
		for _, r := range rows {
			if r.ID == id {
				if out, err = view(r, r.State); err != nil {
					return err
				}
			}
		}
		return recordEnd(ctx, tx, c.Actor(), out, len(rows)-1)
	})
	return out, err
}

func usableAgent(ctx context.Context, q *dbq.Queries, org ids.OrgID, id ids.UUID) (dbq.PcAgent, error) {
	a, err := q.LockAgent(ctx, org, id)
	if db.IsNoRows(err) {
		return a, ErrAgentNotFound
	} else if err != nil {
		return a, err
	}
	if !adomain.State(a.State).Usable() || a.EnvironmentID == nil {
		return a, ErrAgentUnusable
	}
	return a, nil
}

func admittedInstance(ctx context.Context, q *dbq.Queries, org ids.OrgID, agent, id ids.UUID) error {
	in, err := q.GetInstance(ctx, org, id)
	if db.IsNoRows(err) || (err == nil && (in.AgentID != agent || in.State != "ADMITTED")) {
		return ErrInstance
	}
	return err
}

func record(ctx context.Context, tx db.TenantTx, actor evdomain.Actor, name string, r Run) error {
	details := map[string]string{
		"agent_id": r.AgentID.String(), "principal_source": r.PrincipalSource,
		"principal": r.Principal.Kind + ":" + r.Principal.ID, "depth": strconv.Itoa(r.Depth),
	}
	if r.InstanceID != nil {
		details["instance_id"] = r.InstanceID.String()
	}
	if r.Simulated {
		details["simulated"] = "true"
	}
	if r.ParentRunID != nil {
		details["parent_run_id"] = r.ParentRunID.String()
	}
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: actor, Outcome: audit.Success, Object: &audit.Object{Type: "run", ID: r.ID.String()}, Details: details,
	})
	return err
}

func recordEnd(ctx context.Context, tx db.TenantTx, actor evdomain.Actor, r Run, children int) error {
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: "run.ended", Actor: actor, Outcome: audit.Success, Object: &audit.Object{Type: "run", ID: r.ID.String()},
		Details: map[string]string{
			"agent_id": r.AgentID.String(), "reason": r.EndReason, "children_revoked": strconv.Itoa(children),
		},
	})
	return err
}

// Bind checks that a request from instance of agent may use run (HR-022):
// the run is active, of that agent, and bound to that instance, or unbound
// and then bound to it by a conditional update, so concurrent first uses
// bind exactly one instance. Anything else is run_mismatch. It returns
// when the run expires, which bounds anything that lives on the run, such
// as an MCP session (G0 M6 design decision 13).
func (s *Service) Bind(ctx context.Context, org ids.OrgID, run, agent, instance ids.UUID) (time.Time, error) {
	var expires time.Time
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		r, err := q.GetRun(ctx, org, run)
		if db.IsNoRows(err) {
			return pap.Err(pap.CodeRunMismatch)
		} else if err != nil {
			return err
		}
		if r.EffectiveState != "ACTIVE" || r.PcRun.AgentID != agent {
			return pap.Err(pap.CodeRunMismatch)
		}
		expires = r.PcRun.ExpiresAt
		if r.PcRun.InstanceID == nil {
			n, err := q.BindRunInstance(ctx, &instance, org, run)
			if err != nil {
				return err
			}
			if n == 1 {
				return nil
			}
			if r, err = q.GetRun(ctx, org, run); err != nil {
				return err
			}
		}
		if r.PcRun.InstanceID == nil || *r.PcRun.InstanceID != instance {
			return pap.Err(pap.CodeRunMismatch)
		}
		return nil
	})
	if err != nil {
		return time.Time{}, err
	}
	return expires, nil
}

// Grants loads grants inside a caller's transaction (the grants store).
type Grants interface {
	// GrantInTx returns the grant's current revision; found is false when
	// the org has no such grant.
	GrantInTx(ctx context.Context, tx db.TenantTx, org ids.OrgID, id gdomain.GrantID) (g gdomain.Grant, found bool, err error)
}

// WithGrants lets StartRun bind runs to grants (M4); without it a request
// naming a grant is refused.
func (s *Service) WithGrants(g Grants) *Service {
	s.grants = g
	return s
}

// bindGrant checks, in the run's own transaction, that the run may use a
// root grant, and caps the run's expiry at the grant's (HR-022, PN-002.5;
// G0 M4 part 2, design decision 19). The org containment row is taken FOR
// SHARE before the grant is read, so a concurrent revocation is either seen
// here or ordered after this run exists, and then revokes its authority
// (design decision 8).
func (s *Service) bindGrant(ctx context.Context, tx db.TenantTx, org ids.OrgID, id ids.UUID, p *dbq.InsertRunParams) error {
	if s.grants == nil {
		return ErrGrantsUnavailable
	}
	q := dbq.New(tx)
	// The containment row is created on first use.
	if err := q.InsertContainment(ctx, org); err != nil {
		return err
	}
	if _, err := q.ShareContainment(ctx, org); err != nil {
		return err
	}
	gid, err := gdomain.ParseGrantID(id.String())
	if err != nil {
		return ErrGrantNotFound
	}
	g, found, err := s.grants.GrantInTx(ctx, tx, org, gid)
	if err != nil {
		return err
	}
	if !found {
		return ErrGrantNotFound
	}
	if !g.IsRoot() {
		return ErrGrantDelegated
	}
	// A grant an automation issued binds only to the run StartForAutomationTx
	// starts for its execution (G0 M11 part 2 D56).
	if !g.Ceiling.IsZero() && (p.AutomationExecutionID == nil || *p.AutomationExecutionID != g.Execution) {
		return ErrGrantMismatch
	}
	now, err := q.DBNow(ctx)
	if err != nil {
		return err
	}
	if code, ok := g.Usable(now); !ok {
		return pcerr.New(pcerr.FailedPrecondition, code, "the grant cannot be used now")
	}
	var instance ids.UUID
	if p.InstanceID != nil {
		instance = *p.InstanceID
	}
	principal := gdomain.Principal{Kind: gdomain.PrincipalUser}
	switch {
	case p.PrincipalUserID != nil:
		principal.ID = *p.PrincipalUserID
	case p.PrincipalSaID != nil:
		principal = gdomain.Principal{Kind: gdomain.PrincipalServiceAccount, ID: *p.PrincipalSaID}
	}
	if !g.Covers(p.AgentID, instance, principal, p.EnvironmentID) {
		return ErrGrantMismatch
	}
	p.GrantID, p.NotAfter = &id, &g.ExpiresAt
	return nil
}
