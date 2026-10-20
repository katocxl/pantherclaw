// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package enforcementpoints registers the third-party policy enforcement
// points that ask the AuthZEN decision endpoint for decisions (G0 M14
// D26-D29; PN-023, ADR-0019; HR-317). A point is a service account, its
// subject, bound to the connections it fronts: agent_held and
// target_enforced http or mcp connections only, since a pantherclaw_held
// connection's credential is only ever placed by a gateway.
//
// Only a person holding enforcement_point.manage changes a point
// (enforcement_point.manage is bindable to service accounts through Org
// Admin, so the use cases refuse every other caller; D62). A point is
// created PENDING proposing its connections; a person who stepped up with
// one of their own security keys on the confirm page activates it, which
// binds them. Narrowing an ACTIVE point applies at once; widening is
// proposed and confirmed the same way while the point keeps its current
// connections. Disabling is final. Every change is audited.
package enforcementpoints

import (
	"context"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Bounds.
const (
	DefaultRatePerSecond = 50
	MaxRatePerSecond     = 1000
	MaxConnections       = 50
	MaxDescription       = 500
	// MaxPoints bounds an org's points that are not disabled.
	MaxPoints = 100
)

// Point states.
const (
	StatePending  = "PENDING"
	StateActive   = "ACTIVE"
	StateDisabled = "DISABLED"
)

// PagePath is the confirm page's prefix: PagePath + id + "/confirm".
const PagePath = "/enforcement-points/"

// Errors.
var (
	ErrHuman    = pcerr.New(pcerr.PermissionDenied, "HUMAN_ONLY", "only a person manages enforcement points")
	ErrNotFound = pcerr.New(pcerr.NotFound, "ENFORCEMENT_POINT_NOT_FOUND", "enforcement point not found")
	ErrExists   = pcerr.New(pcerr.AlreadyExists, "ENFORCEMENT_POINT_EXISTS",
		"an enforcement point with that name, or for that service account, exists already")
	ErrInvalid = pcerr.New(pcerr.InvalidArgument, "ENFORCEMENT_POINT_INVALID",
		"an enforcement point needs a name, a description of at most 500 characters, a service account, "+
			"1 to 50 distinct connections and a rate of 1 to 1000 a second")
	ErrState   = pcerr.New(pcerr.FailedPrecondition, "ENFORCEMENT_POINT_STATE", "the enforcement point is not in a state that allows this")
	ErrNothing = pcerr.New(pcerr.FailedPrecondition, "NOTHING_TO_CONFIRM", "the enforcement point has no proposed connections to confirm")
	ErrSubject = pcerr.New(pcerr.FailedPrecondition, "ENFORCEMENT_POINT_SUBJECT",
		"the service account does not exist or is disabled")
	// ErrNotBindable: an enforcement point fronts only agent_held and
	// target_enforced http or mcp connections that are not retired (D27).
	ErrNotBindable = pcerr.New(pcerr.FailedPrecondition, "CONNECTION_NOT_BINDABLE",
		"an enforcement point fronts only agent_held or target_enforced http or mcp connections that are not retired")
	ErrTooMany = pcerr.New(pcerr.ResourceExhausted, "ENFORCEMENT_POINTS_FULL", "the org has 100 enforcement points; disable one first")
)

var nameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// Point is an enforcement point.
type Point struct {
	ID                ids.UUID
	Name              string
	Description       string
	ServiceAccount    ids.UUID
	Connections       []ids.UUID
	Proposed          []ids.UUID
	RatePerSecond     int
	State             string
	CreatedBy         ids.UUID
	CreatedAt         time.Time
	ActivatedBy       *ids.UUID
	ActivatedAt       *time.Time
	ActivatedSecurity *ids.UUID
	DisabledAt        *time.Time
}

// NewPoint describes a point to create.
type NewPoint struct {
	Name, Description string
	ServiceAccount    ids.UUID
	Connections       []ids.UUID
	RatePerSecond     int
}

// Service serves the enforcement point use cases.
type Service struct {
	pool *db.Pool
}

// New returns the use cases.
func New(pool *db.Pool) *Service { return &Service{pool: pool} }

// manager is a person holding enforcement_point.manage on the org (D62).
func manager(ctx context.Context) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	if err := c.Require(td.PermEnforcementPointManage, td.OrgPath(c.Org)); err != nil {
		return c, err
	}
	if !c.Human() {
		return c, ErrHuman
	}
	return c, nil
}

// reader holds enforcement_point.manage (a person or a service).
func reader(ctx context.Context) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	return c, c.Require(td.PermEnforcementPointManage, td.OrgPath(c.Org))
}

func pointOf(r dbq.GetEnforcementPointRow) Point {
	return Point{
		ID: r.ID, Name: r.Name, Description: r.Description, ServiceAccount: r.ServiceAccountID,
		Connections: r.ConnectionIds, Proposed: r.ProposedConnections, RatePerSecond: int(r.RatePerSecond), State: r.State,
		CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt, ActivatedBy: r.ActivatedBy, ActivatedAt: r.ActivatedAt,
		ActivatedSecurity: r.ActivatedCredential, DisabledAt: r.DisabledAt,
	}
}

func get(ctx context.Context, q *dbq.Queries, org ids.OrgID, id ids.UUID) (Point, error) {
	r, err := q.GetEnforcementPoint(ctx, org, id)
	if db.IsNoRows(err) {
		return Point{}, ErrNotFound
	} else if err != nil {
		return Point{}, err
	}
	return pointOf(r), nil
}

// normalized returns the set sorted and checks its size and uniqueness.
func normalized(conns []ids.UUID) ([]ids.UUID, bool) {
	out := slices.Clone(conns)
	slices.SortFunc(out, func(a, b ids.UUID) int { return strings.Compare(a.String(), b.String()) })
	if len(out) == 0 || len(out) > MaxConnections || len(slices.Compact(slices.Clone(out))) != len(out) ||
		slices.ContainsFunc(out, ids.UUID.IsZero) {
		return nil, false
	}
	return out, true
}

// Bindable reports whether an enforcement point may front a connection of
// this kind, access mode and state (D27).
func Bindable(kind, accessMode, state string) bool {
	return (kind == "http" || kind == "mcp") && (accessMode == "agent_held" || accessMode == "target_enforced") &&
		state != "RETIRED"
}

// bindable checks that every connection exists in the org and may be
// fronted.
func bindable(ctx context.Context, q *dbq.Queries, org ids.OrgID, conns []ids.UUID) error {
	rows, err := q.EnforcementPointBindable(ctx, org, conns)
	if err != nil {
		return err
	}
	if len(rows) != len(conns) {
		return ErrNotBindable
	}
	for _, r := range rows {
		if !Bindable(r.Kind, r.AccessMode, r.State) {
			return ErrNotBindable
		}
	}
	return nil
}

func record(ctx context.Context, tx db.TenantTx, c tenancy.Caller, name string, id ids.UUID, details map[string]string) error {
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: c.Actor(), Outcome: audit.Success,
		Object: &audit.Object{Type: "enforcement_point", ID: id.String()}, Details: details,
	})
	return err
}

func joined(conns []ids.UUID) string {
	s := make([]string, len(conns))
	for i, c := range conns {
		s[i] = c.String()
	}
	return strings.Join(s, ",")
}

// Create stores a PENDING point proposing its connections. It asks for
// nothing until a person activates it with a step-up.
func (s *Service) Create(ctx context.Context, in NewPoint) (Point, error) {
	c, err := manager(ctx)
	if err != nil {
		return Point{}, err
	}
	in.Description = strings.TrimSpace(in.Description)
	if in.RatePerSecond == 0 {
		in.RatePerSecond = DefaultRatePerSecond
	}
	conns, ok := normalized(in.Connections)
	if !ok || !nameRe.MatchString(in.Name) || utf8.RuneCountInString(in.Description) > MaxDescription ||
		strings.ContainsFunc(in.Description, func(r rune) bool { return unicode.IsControl(r) && r != '\n' }) ||
		in.ServiceAccount.IsZero() || in.RatePerSecond < 1 || in.RatePerSecond > MaxRatePerSecond {
		return Point{}, ErrInvalid
	}
	id := ids.NewV7()
	var out Point
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		sa, err := q.EnforcementPointSubject(ctx, c.Org, in.ServiceAccount)
		if db.IsNoRows(err) || (err == nil && sa.State != "ACTIVE") {
			return ErrSubject
		} else if err != nil {
			return err
		}
		if n, err := q.CountLiveEnforcementPoints(ctx, c.Org); err != nil {
			return err
		} else if n >= MaxPoints {
			return ErrTooMany
		}
		if err := bindable(ctx, q, c.Org, conns); err != nil {
			return err
		}
		err = q.InsertEnforcementPoint(ctx, dbq.InsertEnforcementPointParams{
			OrgID: c.Org, ID: id, Name: in.Name, Description: in.Description, ServiceAccountID: in.ServiceAccount,
			ProposedConnections: conns, RatePerSecond: int32(in.RatePerSecond), CreatedBy: c.Principal.ID, //nolint:gosec // 1..1000
		})
		if db.IsUniqueViolation(err) {
			return ErrExists
		} else if err != nil {
			return err
		}
		if err := record(ctx, tx, c, "authzen.enforcement_point_created", id, map[string]string{
			"name": in.Name, "service_account_id": in.ServiceAccount.String(), "proposed_connections": joined(conns),
		}); err != nil {
			return err
		}
		out, err = get(ctx, q, c.Org, id)
		return err
	})
	return out, err
}

// Activate confirms a point's proposed connections and binds them: a
// PENDING point becomes ACTIVE, an ACTIVE one gets its widened set. It
// needs a person holding enforcement_point.manage with a fresh step-up of
// one of their own keys; su is nil over the API, which refuses (D29, D62).
// The proposed connections are checked again, as they are now.
func (s *Service) Activate(ctx context.Context, id ids.UUID, su *stepup.StepUp) (Point, error) {
	c, err := manager(ctx)
	if err != nil {
		return Point{}, err
	}
	if su == nil {
		return Point{}, stepup.ErrStepUp
	}
	var out Point
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		if err := stepup.Check(ctx, tx, c, *su, now); err != nil {
			return err
		}
		p, err := q.LockEnforcementPoint(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		switch {
		case p.State == StateDisabled:
			return ErrState
		case len(p.ProposedConnections) == 0:
			return ErrNothing
		}
		if err := bindable(ctx, q, c.Org, p.ProposedConnections); err != nil {
			return err
		}
		if _, err := q.UnbindEnforcementPointConnections(ctx, c.Org, id, p.ProposedConnections); err != nil {
			return err
		}
		if err := q.BindEnforcementPointConnections(ctx, c.Org, id, p.ProposedConnections); err != nil {
			return err
		}
		n, err := q.ActivateEnforcementPoint(ctx, dbq.ActivateEnforcementPointParams{
			ActivatedBy: &c.Principal.ID, ActivatedCredential: &su.Credential, OrgID: c.Org, ID: id,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrState
		}
		if err := record(ctx, tx, c, "authzen.enforcement_point_activated", id, map[string]string{
			"connections": joined(p.ProposedConnections), "previous_connections": joined(p.ConnectionIds),
			"security_key": su.Credential.String(),
		}); err != nil {
			return err
		}
		out, err = get(ctx, q, c.Org, id)
		return err
	})
	return out, err
}

// UpdateConnections replaces a point's connections. A set within an
// ACTIVE point's current one applies at once and drops any proposal; any
// other set is proposed and waits for Activate (pending reports so).
func (s *Service) UpdateConnections(ctx context.Context, id ids.UUID, conns []ids.UUID) (out Point, pending bool, err error) {
	c, err := manager(ctx)
	if err != nil {
		return Point{}, false, err
	}
	set, ok := normalized(conns)
	if !ok {
		return Point{}, false, ErrInvalid
	}
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		p, err := q.LockEnforcementPoint(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if p.State == StateDisabled {
			return ErrState
		}
		narrows := p.State == StateActive && !slices.ContainsFunc(set, func(x ids.UUID) bool { return !slices.Contains(p.ConnectionIds, x) })
		if narrows {
			if _, err := q.UnbindEnforcementPointConnections(ctx, c.Org, id, set); err != nil {
				return err
			}
			if _, err := q.ProposeEnforcementPointConnections(ctx, nil, c.Org, id); err != nil {
				return err
			}
			if err := record(ctx, tx, c, "authzen.enforcement_point_narrowed", id, map[string]string{
				"connections": joined(set), "previous_connections": joined(p.ConnectionIds),
			}); err != nil {
				return err
			}
		} else {
			if err := bindable(ctx, q, c.Org, set); err != nil {
				return err
			}
			if _, err := q.ProposeEnforcementPointConnections(ctx, set, c.Org, id); err != nil {
				return err
			}
			if err := record(ctx, tx, c, "authzen.enforcement_point_proposed", id, map[string]string{
				"proposed_connections": joined(set), "connections": joined(p.ConnectionIds),
			}); err != nil {
				return err
			}
			pending = true
		}
		out, err = get(ctx, q, c.Org, id)
		return err
	})
	if err != nil {
		return Point{}, false, err
	}
	return out, pending, nil
}

// Disable disables a point for good: it asks for no decision again.
func (s *Service) Disable(ctx context.Context, id ids.UUID) (Point, error) {
	c, err := manager(ctx)
	if err != nil {
		return Point{}, err
	}
	var out Point
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		n, err := q.DisableEnforcementPoint(ctx, &c.Principal.ID, c.Org, id)
		if err != nil {
			return err
		}
		if n == 0 {
			if _, err := get(ctx, q, c.Org, id); err != nil {
				return err
			}
			return ErrState
		}
		if err := record(ctx, tx, c, "authzen.enforcement_point_disabled", id, nil); err != nil {
			return err
		}
		out, err = get(ctx, q, c.Org, id)
		return err
	})
	return out, err
}

// Get returns one point.
func (s *Service) Get(ctx context.Context, id ids.UUID) (Point, error) {
	c, err := reader(ctx)
	if err != nil {
		return Point{}, err
	}
	var out Point
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = get(ctx, dbq.New(tx), c.Org, id)
		return err
	})
	return out, err
}

// List lists the org's points by name.
func (s *Service) List(ctx context.Context) ([]Point, error) {
	c, err := reader(ctx)
	if err != nil {
		return nil, err
	}
	var out []Point
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListEnforcementPoints(ctx, c.Org)
		for _, r := range rows {
			out = append(out, pointOf(dbq.GetEnforcementPointRow(r)))
		}
		return err
	})
	return out, err
}
