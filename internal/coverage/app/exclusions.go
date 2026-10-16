// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	"github.com/katocxl/pantherclaw/internal/protect"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Errors of the exclusion use cases.
var (
	ErrExclusion       = pcerr.New(pcerr.InvalidArgument, "INVALID_EXCLUSION", "an exclusion needs a written reason of 10 to 1,000 characters, an expiry of 1 to 90 days, a known operation form and a route kind other than a channel")
	operationPattern   = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_]+){1,7}$`)
	ErrExclusionClosed = pcerr.New(pcerr.FailedPrecondition, "EXCLUSION_NOT_ACTIVE", "the exclusion is no longer active")
)

// ExclusionRequest describes an exclusion. A nil Agent excludes for every
// agent of the connection, a nil Operation every operation, and an empty
// Kind the whole scope.
type ExclusionRequest struct {
	Connection    ids.UUID
	Agent         *ids.UUID
	Operation     *string
	Kind          domain.RouteKind
	Reason        string
	ExpiresInDays int
}

func (r ExclusionRequest) valid() bool {
	reason := strings.TrimSpace(r.Reason)
	n := utf8.RuneCountInString(reason)
	kindOK := r.Kind == "" || (r.Kind != domain.KindChannel && slices.Contains(domain.EquivalentKinds, r.Kind))
	return n >= 10 && n <= 1000 && r.ExpiresInDays >= 1 && r.ExpiresInDays <= 90 && kindOK &&
		(r.Operation == nil || operationPattern.MatchString(*r.Operation))
}

// excluder is the caller, who must be a person signed in as themselves
// holding coverage.manage at org scope (HR-212).
func excluder(ctx context.Context) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	if !c.Human() || c.Credential == tenancy.CredAPIKey {
		return c, ErrHumanOnly
	}
	return c, c.Require(td.PermCoverageManage, td.OrgPath(c.Org))
}

// CreateExclusion records an exclusion (HR-212): a weakening change, so
// only a person makes one, with a written reason and an expiry. It never
// raises a state; it is audited, and the scopes it affects are reassessed
// so it is shown with the coverage it changes. With COVERAGE_EXCLUSION
// protected, it waits for a distinct publisher instead (G0 M11 D42,
// HR-292) and returns protect.ErrPending.
func (s *Service) CreateExclusion(ctx context.Context, r ExclusionRequest) (dbq.PcCoverageExclusion, error) {
	var out dbq.PcCoverageExclusion
	if !r.valid() {
		return out, ErrExclusion
	}
	c, err := excluder(ctx)
	if err != nil {
		return out, err
	}
	var held *protect.PendingError
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, held, err = s.createExclusion(ctx, tx, c, r)
		return err
	})
	if err == nil && held != nil {
		return dbq.PcCoverageExclusion{}, held
	}
	return out, err
}

// ApplyProtectedExclusion re-runs a confirmed protected exclusion as its
// author (a protect.Applier).
func (s *Service) ApplyProtectedExclusion(ctx context.Context, tx db.TenantTx, author tenancy.Caller, payload []byte) error {
	var r ExclusionRequest
	if err := json.Unmarshal(payload, &r); err != nil || !r.valid() {
		return ErrExclusion
	}
	c, err := excluder(tenancy.WithCaller(ctx, author))
	if err != nil {
		return err
	}
	_, held, err := s.createExclusion(ctx, tx, c, r)
	if err == nil && held != nil {
		return held
	}
	return err
}

func (s *Service) createExclusion(ctx context.Context, tx db.TenantTx, c tenancy.Caller, r ExclusionRequest) (dbq.PcCoverageExclusion, *protect.PendingError, error) {
	var out dbq.PcCoverageExclusion
	q := dbq.New(tx)
	if b, err := q.CoverageBinding(ctx, c.Org, r.Connection); db.IsNoRows(err) || (err == nil && b.State == "RETIRED") {
		return out, nil, ErrNotFound
	} else if err != nil {
		return out, nil, err
	}
	if r.Agent != nil {
		if _, err := q.GetAgent(ctx, c.Org, *r.Agent); db.IsNoRows(err) {
			return out, nil, ErrNotFound
		} else if err != nil {
			return out, nil, err
		}
	}
	var kind *string
	if r.Kind != "" {
		k := string(r.Kind)
		kind = &k
	}
	held, err := s.Protect.Hold(ctx, tx, c, exclusionChange(r), func(ctx context.Context) error {
		var err error
		out, err = q.InsertCoverageExclusion(ctx, dbq.InsertCoverageExclusionParams{
			OrgID: c.Org, ID: ids.NewV7(), AgentID: r.Agent, ConnectionID: r.Connection, Operation: r.Operation,
			RouteKind: kind, Reason: strings.TrimSpace(r.Reason), CreatedBy: c.Principal.ID, ExpiresInDays: int32(r.ExpiresInDays), //nolint:gosec // G115: 1..90
		})
		if err != nil {
			return err
		}
		if err := s.excluded(ctx, tx, c, out, "coverage.exclusion_created"); err != nil {
			return err
		}
		return s.notifyExcluded(ctx, tx, c, out, r.ExpiresInDays)
	})
	return out, held, err
}

// exclusionChange is an exclusion as a protected change: its scope is the
// subject, so a newer request for the same scope replaces an older one.
func exclusionChange(r ExclusionRequest) protect.Change {
	agent, op := "*", "*"
	if r.Agent != nil {
		agent = r.Agent.String()
	}
	if r.Operation != nil {
		op = *r.Operation
	}
	scope := r.Connection.String() + "/" + agent + "/" + op + "/" + string(r.Kind)
	return protect.Change{
		Category: protect.CoverageExclusion, Surface: protect.SurfaceExclusionCreate, Subject: scope,
		Summary: map[string]string{
			"connection": r.Connection.String(), "agent": agent, "operation": op, "route_kind": string(r.Kind),
			"expires_in_days": strconv.Itoa(r.ExpiresInDays), "reason": strings.TrimSpace(r.Reason),
		},
		Widening: []string{"coverage_exclusion"}, Payload: r,
	}
}

// excluded audits an exclusion change and asks for the reassessment of
// the scopes it applies to.
func (s *Service) excluded(ctx context.Context, tx db.TenantTx, c tenancy.Caller, x dbq.PcCoverageExclusion, name string) error {
	details := map[string]string{
		"connection": x.ConnectionID.String(), "expires": x.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"),
		"reason_length": strconv.Itoa(utf8.RuneCountInString(x.Reason)),
	}
	if x.AgentID != nil {
		details["agent"] = x.AgentID.String()
	}
	if x.Operation != nil {
		details["operation"] = *x.Operation
	}
	if x.RouteKind != nil {
		details["route_kind"] = *x.RouteKind
	}
	if _, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: c.Actor(), Outcome: audit.Success, Object: &audit.Object{Type: "coverage_exclusion", ID: x.ID.String()},
		Details: details,
	}); err != nil {
		return err
	}
	return s.RecordInvalidation(ctx, tx, domain.Invalidation{
		Kind: domain.InvExclusion, Connection: x.ConnectionID, Agent: x.AgentID, Subject: &x.ID,
	})
}

// Notifier enqueues notifications (M5).
type Notifier interface {
	Enqueue(ctx context.Context, tx db.TenantTx, m napp.Message) (napp.Enqueued, error)
}

// notifyExcluded tells the org's security recipients of a new exclusion,
// a weakening change (HR-212), with its scope in fixed words and never its
// reason.
func (s *Service) notifyExcluded(ctx context.Context, tx db.TenantTx, c tenancy.Caller, x dbq.PcCoverageExclusion, days int) error {
	if s.Notify == nil {
		return nil
	}
	conn, err := dbq.New(tx).GetConnection(ctx, c.Org, x.ConnectionID)
	if err != nil {
		return err
	}
	scope := "the whole scope"
	if x.RouteKind != nil {
		scope = "the " + *x.RouteKind + " route"
	}
	if x.Operation != nil {
		scope += " of " + *x.Operation
	} else {
		scope += " of every operation"
	}
	if x.AgentID != nil {
		scope += " for agent " + x.AgentID.String()
	} else {
		scope += " for every agent"
	}
	_, err = s.Notify.Enqueue(ctx, tx, napp.Message{Org: c.Org, Type: "security.coverage_excluded", Params: map[string]string{
		"user": c.Principal.String(), "connection": conn.Name, "scope": scope, "days": strconv.Itoa(days),
	}})
	return err
}

// RevokeExclusion ends an active exclusion at once (audited).
func (s *Service) RevokeExclusion(ctx context.Context, id ids.UUID) (dbq.PcCoverageExclusion, error) {
	var out dbq.PcCoverageExclusion
	c, err := excluder(ctx)
	if err != nil {
		return out, err
	}
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = dbq.New(tx).RevokeCoverageExclusion(ctx, &c.Principal.ID, c.Org, id)
		if db.IsNoRows(err) {
			return ErrExclusionClosed
		} else if err != nil {
			return err
		}
		return s.excluded(ctx, tx, c, out, "coverage.exclusion_revoked")
	})
	return out, err
}

// Exclusion is an exclusion as listed, with ACTIVE past its expiry read as
// EXPIRED.
type Exclusion struct {
	dbq.PcCoverageExclusion
	EffectiveState string
}

// ListExclusions lists the org's exclusions newest first; the caller holds
// coverage.read at org scope.
func (s *Service) ListExclusions(ctx context.Context, connection *ids.UUID, size int32, token string) ([]Exclusion, string, error) {
	p, err := page.Parse(size, token)
	if err != nil {
		return nil, "", err
	}
	var out []Exclusion
	var next string
	err = s.read(ctx, func(ctx context.Context, r *readers) error {
		if err := r.c.Require(td.PermCoverageRead, td.OrgPath(r.c.Org)); err != nil {
			return err
		}
		rows, err := r.q.ListCoverageExclusionsPage(ctx, dbq.ListCoverageExclusionsPageParams{
			OrgID: r.c.Org, ConnectionID: connection, Before: cursor(p), MaxRows: p.Limit(),
		})
		if err != nil {
			return err
		}
		rows, next = page.Finish(p, rows, func(x dbq.ListCoverageExclusionsPageRow) ids.UUID { return x.ID })
		for _, x := range rows {
			out = append(out, Exclusion{PcCoverageExclusion: dbq.PcCoverageExclusion{
				OrgID: x.OrgID, ID: x.ID, AgentID: x.AgentID, ConnectionID: x.ConnectionID, Operation: x.Operation,
				RouteKind: x.RouteKind, Reason: x.Reason, State: x.State, CreatedBy: x.CreatedBy, CreatedAt: x.CreatedAt,
				ExpiresAt: x.ExpiresAt, RevokedBy: x.RevokedBy, RevokedAt: x.RevokedAt,
			}, EffectiveState: x.EffectiveState})
		}
		return nil
	})
	return out, next, err
}

// ProtectedExclusionState is the state a protected exclusion's re-run must
// still find (a protect.State): the connection's coverage binding, its
// revision and state, and the agent.
func (s *Service) ProtectedExclusionState(ctx context.Context, tx db.TenantTx, payload []byte) ([]byte, error) {
	var r ExclusionRequest
	if err := json.Unmarshal(payload, &r); err != nil {
		return nil, ErrExclusion
	}
	q := dbq.New(tx)
	state := "none"
	if b, err := q.CoverageBinding(ctx, tx.OrgID(), r.Connection); err == nil {
		state = b.State
	} else if !db.IsNoRows(err) {
		return nil, err
	}
	// The connection itself, by revision: a change to it voids the request
	// (D90 L1).
	if conn, err := q.GetConnection(ctx, tx.OrgID(), r.Connection); err == nil {
		state += "/" + strconv.Itoa(int(conn.Revision)) + "/" + conn.State
	} else if !db.IsNoRows(err) {
		return nil, err
	}
	if r.Agent != nil {
		if _, err := q.GetAgent(ctx, tx.OrgID(), *r.Agent); db.IsNoRows(err) {
			state += "/no-agent"
		} else if err != nil {
			return nil, err
		}
	}
	return []byte(state), nil
}
