// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package simulation predicts what a stored policy version would have
// decided over an org's recorded decisions (G0 M11.1 D15; F187–F192,
// F287; HR-232, HR-237; Team edition).
//
// A simulation is a bounded batch replay run by a background job: the
// recorded decisions of a window of at most 30 days inside retention,
// newest first and at most MaxEvaluations of them. Each is replayed with
// the M7 replay engine once with the policy it was decided under and once
// with the version (the method of D13), and counted in one category (D5).
// A decision whose replay does not reproduce, or that the version cannot
// evaluate on the recorded inputs, is unevaluable, never guessed (R-26).
//
// A simulation only reads: the engine holds read ports and reads in READ
// ONLY transactions, and the store writes only the simulation's own rows
// (HR-232). Its report and samples carry ids, decisions and reason codes,
// never a recorded input value; the inputs of a sample are read through
// ReplayDecision with its own permission (HR-237). Nothing in
// internal/authority imports this package.
package simulation

import (
	"context"
	"crypto/sha256"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"strconv"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Bounds (D15).
const (
	MaxDays               = 30
	DefaultDays           = 7
	MaxEvaluations        = 50000
	DefaultMaxEvaluations = 10000
	// SamplesPerGroup is the most samples kept per category and operation.
	SamplesPerGroup = 25
)

// State is where a simulation is in its life.
type State string

// States.
const (
	Queued    State = "QUEUED"
	Running   State = "RUNNING"
	Done      State = "DONE"
	Failed    State = "FAILED"
	Cancelled State = "CANCELLED"
)

// Errors of the simulation use cases.
var (
	ErrEdition         = pcerr.New(pcerr.PermissionDenied, "EDITION_REQUIRED", "policy simulation needs the Team edition or above")
	ErrNotFound        = pcerr.New(pcerr.NotFound, "SIMULATION_NOT_FOUND", "simulation not found")
	ErrVersionNotFound = pcerr.New(pcerr.NotFound, "POLICY_VERSION_NOT_FOUND", "policy version not found")
	ErrBusy            = pcerr.New(pcerr.FailedPrecondition, "SIMULATION_RUNNING",
		"a simulation is already queued or running for this organization: wait for it or cancel it")
	ErrWindow = pcerr.New(pcerr.InvalidArgument, "INVALID_SIMULATION_WINDOW",
		"a simulation covers 1 to 30 days, inside the retention of decision receipts and replay inputs")
	ErrBounds   = pcerr.New(pcerr.InvalidArgument, "INVALID_SIMULATION_BOUNDS", "a simulation replays 1 to 50 000 decisions")
	ErrFinished = pcerr.New(pcerr.FailedPrecondition, "SIMULATION_FINISHED", "the simulation has already finished")
	ErrCategory = pcerr.New(pcerr.InvalidArgument, "INVALID_SIMULATION_CATEGORY", "unknown category")
	ErrUnwired  = pcerr.New(pcerr.Unavailable, "SIMULATION_UNAVAILABLE", "policy simulation is not available on this server")
)

// Cursor is the worker's keyset position: the last recorded decision it
// counted, newest first.
type Cursor struct {
	Created     time.Time
	Transaction ids.UUID
	Evaluation  int
}

// Simulation is one simulation and its report so far.
type Simulation struct {
	ID            ids.UUID
	Version       ids.UUID
	ContentDigest [32]byte
	WindowStart   time.Time
	WindowEnd     time.Time
	Max           int
	State         State
	Evaluated     int
	Report        Report
	Cursor        *Cursor
	RequestedBy   string
	Created       time.Time
	Started       *time.Time
	Finished      *time.Time
	Error         string
}

// Recorded is a recorded decision of the window: ids, its agent and its
// operation.
type Recorded struct {
	Transaction ids.UUID
	Evaluation  int
	Created     time.Time
	Agent       ids.UUID
	Operation   string
}

// NewSimulation is what a request stores.
type NewSimulation struct {
	ID            ids.UUID
	Version       ids.UUID
	ContentDigest [32]byte
	Days          int
	Max           int
	RequestedBy   string
}

// SampleFilter narrows a sample listing.
type SampleFilter struct {
	Category  Category
	Operation string
}

// SampleKey is a sample's position in a listing.
type SampleKey struct {
	Transaction ids.UUID
	Evaluation  int
}

// Tx is the simulation store inside one tenant transaction. It writes only
// the simulation's own rows, its job and its audit events (HR-232).
type Tx interface {
	// RetentionDays is how far back recorded decisions can still be
	// replayed now.
	RetentionDays(ctx context.Context) (int, error)
	// Insert stores a queued simulation over the window ending now; ErrBusy
	// when the org has one queued or running.
	Insert(ctx context.Context, s NewSimulation) (Simulation, error)
	// Get returns a simulation (locked for update when lock), or ErrNotFound.
	Get(ctx context.Context, id ids.UUID, lock bool) (Simulation, error)
	List(ctx context.Context, before ids.UUID, limit int32) ([]Simulation, error)
	// Start moves a queued simulation to RUNNING; false when it was not
	// queued (a conditional update).
	Start(ctx context.Context, id ids.UUID) (Simulation, bool, error)
	// Advance stores a running simulation's progress, state and report;
	// false when it was no longer running.
	Advance(ctx context.Context, s Simulation) (Simulation, bool, error)
	// Cancel stops a queued or running simulation; false when it had
	// finished.
	Cancel(ctx context.Context, id ids.UUID) (Simulation, bool, error)
	// Receipts returns the next recorded decisions of s's window after its
	// cursor, newest first.
	Receipts(ctx context.Context, s Simulation, limit int) ([]Recorded, error)
	// SampleCounts counts the stored samples by category and operation.
	SampleCounts(ctx context.Context, id ids.UUID) (map[Category]map[string]int, error)
	InsertSample(ctx context.Context, id ids.UUID, s Sample) error
	Samples(ctx context.Context, id ids.UUID, f SampleFilter, after SampleKey, limit int32) ([]Sample, error)
	// Enqueue adds the simulation's job in this transaction.
	Enqueue(ctx context.Context, id ids.UUID) error
	// Audit records an event in this transaction.
	Audit(ctx context.Context, ev audit.Event) error
}

// Store runs fn in a tenant transaction for org.
type Store interface {
	InTx(ctx context.Context, org ids.OrgID, readOnly bool, fn func(ctx context.Context, tx Tx) error) error
}

// Versions reads stored policy versions (replay.Source implements it);
// ErrNotFound-like errors are reported by IsNotFound.
type Versions interface {
	PolicyVersion(ctx context.Context, org ids.OrgID, id ids.UUID) (*pdomain.Bundle, error)
}

// Editions reports the licence's entitlements.
type Editions interface {
	Current(ctx context.Context) (billing.Entitlements, error)
}

// Service serves simulations.
type Service struct {
	Store    Store
	Versions Versions
	// IsNotFound reports a missing version (replay.ErrNotFound).
	IsNotFound func(error) bool
	// Editions nil: Community, so simulation is refused (fail closed).
	Editions Editions
}

// caller returns the caller holding policy.simulate at the org.
func caller(ctx context.Context) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return tenancy.Caller{}, err
	}
	return c, c.Require(td.PermPolicySimulate, td.OrgPath(c.Org))
}

// team fails closed: without entitlements, or below Team, no simulation.
func (s *Service) team(ctx context.Context) error {
	if s.Editions == nil {
		return ErrEdition
	}
	e, err := s.Editions.Current(ctx)
	if err != nil {
		return err
	}
	if !e.PolicySimulation() {
		return ErrEdition
	}
	return nil
}

// Request asks for a simulation.
type Request struct {
	Version ids.UUID
	// Days is the window ending now (0: DefaultDays).
	Days int
	// Max bounds the decisions replayed (0: DefaultMaxEvaluations).
	Max int
}

// Simulate queues a simulation of a stored policy version over the
// recorded decisions of the last Days days (policy.simulate, Team).
func (s *Service) Simulate(ctx context.Context, in Request) (Simulation, error) {
	c, err := caller(ctx)
	if err != nil {
		return Simulation{}, err
	}
	if err := s.team(ctx); err != nil {
		return Simulation{}, err
	}
	if in.Days == 0 {
		in.Days = DefaultDays
	}
	if in.Max == 0 {
		in.Max = DefaultMaxEvaluations
	}
	if in.Days < 1 || in.Days > MaxDays {
		return Simulation{}, ErrWindow
	}
	if in.Max < 1 || in.Max > MaxEvaluations {
		return Simulation{}, ErrBounds
	}
	if s.Store == nil || s.Versions == nil {
		return Simulation{}, ErrUnwired
	}
	b, err := s.Versions.PolicyVersion(ctx, c.Org, in.Version)
	if err != nil {
		if s.IsNotFound != nil && s.IsNotFound(err) {
			return Simulation{}, ErrVersionNotFound
		}
		return Simulation{}, err
	}
	digest, err := ContentDigest(b)
	if err != nil {
		return Simulation{}, err
	}
	var out Simulation
	err = s.Store.InTx(ctx, c.Org, false, func(ctx context.Context, tx Tx) error {
		keep, err := tx.RetentionDays(ctx)
		if err != nil {
			return err
		}
		if in.Days > keep {
			return ErrWindow
		}
		if out, err = tx.Insert(ctx, NewSimulation{
			ID: ids.NewV7(), Version: in.Version, ContentDigest: digest, Days: in.Days, Max: in.Max, RequestedBy: c.Actor().ID,
		}); err != nil {
			return err
		}
		if err := tx.Enqueue(ctx, out.ID); err != nil {
			return err
		}
		return tx.Audit(ctx, audit.Event{
			Name: "policy.simulation_requested", Actor: c.Actor(), Outcome: audit.Success,
			Object: &audit.Object{Type: "policy_simulation", ID: out.ID.String()},
			Details: map[string]string{
				"version_id": in.Version.String(), "days": strconv.Itoa(in.Days), "max_evaluations": strconv.Itoa(in.Max),
			},
		})
	})
	return out, err
}

// Get returns a simulation and its report (policy.simulate).
func (s *Service) Get(ctx context.Context, id ids.UUID) (Simulation, error) {
	c, err := caller(ctx)
	if err != nil {
		return Simulation{}, err
	}
	var out Simulation
	err = s.Store.InTx(ctx, c.Org, true, func(ctx context.Context, tx Tx) error {
		out, err = tx.Get(ctx, id, false)
		return err
	})
	return out, err
}

// Page is one page of simulations, newest first.
type Page struct {
	Items []Simulation
	Next  string
}

// List lists the org's simulations, newest first (policy.simulate).
func (s *Service) List(ctx context.Context, pr page.Request) (Page, error) {
	c, err := caller(ctx)
	if err != nil {
		return Page{}, err
	}
	var out Page
	err = s.Store.InTx(ctx, c.Org, true, func(ctx context.Context, tx Tx) error {
		rows, err := tx.List(ctx, pr.After, pr.Limit())
		if err != nil {
			return err
		}
		out.Items, out.Next = page.Finish(pr, rows, func(x Simulation) ids.UUID { return x.ID })
		return nil
	})
	return out, err
}

// Cancel stops a queued or running simulation; what it counted stays
// (policy.simulate).
func (s *Service) Cancel(ctx context.Context, id ids.UUID) (Simulation, error) {
	c, err := caller(ctx)
	if err != nil {
		return Simulation{}, err
	}
	var out Simulation
	err = s.Store.InTx(ctx, c.Org, false, func(ctx context.Context, tx Tx) error {
		cur, err := tx.Get(ctx, id, true)
		if err != nil {
			return err
		}
		var ok bool
		if out, ok, err = tx.Cancel(ctx, cur.ID); err != nil {
			return err
		} else if !ok {
			return ErrFinished
		}
		return tx.Audit(ctx, audit.Event{
			Name: "policy.simulation_cancelled", Actor: c.Actor(), Outcome: audit.Success,
			Object:  &audit.Object{Type: "policy_simulation", ID: id.String()},
			Details: map[string]string{"evaluated": strconv.Itoa(out.Evaluated)},
		})
	})
	return out, err
}

// SamplePage is one page of samples.
type SamplePage struct {
	Items []Sample
	Next  string
}

// Samples lists a simulation's samples (policy.simulate): ids, decisions
// and reason codes only (HR-237).
func (s *Service) Samples(ctx context.Context, id ids.UUID, f SampleFilter, size int32, token string) (SamplePage, error) {
	c, err := caller(ctx)
	if err != nil {
		return SamplePage{}, err
	}
	if f.Category != "" && !f.Category.Valid() {
		return SamplePage{}, ErrCategory
	}
	after, err := parseSampleToken(token)
	if err != nil {
		return SamplePage{}, err
	}
	n := page.Default
	if size > 0 {
		n = int(min(size, page.Max))
	}
	var out SamplePage
	err = s.Store.InTx(ctx, c.Org, true, func(ctx context.Context, tx Tx) error {
		if _, err := tx.Get(ctx, id, false); err != nil {
			return err
		}
		rows, err := tx.Samples(ctx, id, f, after, int32(n+1)) //nolint:gosec // G115: at most page.Max+1
		if err != nil {
			return err
		}
		if len(rows) > n {
			rows = rows[:n]
			last := rows[n-1]
			out.Next = sampleToken(SampleKey{Transaction: last.Transaction, Evaluation: last.Evaluation})
		}
		out.Items = rows
		return nil
	})
	return out, err
}

// ContentDigest is the version's content digest: SHA-256 of the JCS form
// of {"id", "rules"}.
//
// Stand-in for D2's domain.ContentDigest until it is on this branch's base.
func ContentDigest(b *pdomain.Bundle) ([32]byte, error) {
	raw, err := json.Marshal(struct {
		ID    string         `json:"id"`
		Rules []pdomain.Rule `json:"rules"`
	}{b.ID, b.Rules})
	if err != nil {
		return [32]byte{}, err
	}
	v := jsontext.Value(raw)
	if err := v.Canonicalize(); err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(v), nil
}
