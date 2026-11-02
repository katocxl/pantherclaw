// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app serves attack campaigns on the server (G0 M25 D305, D309):
// starting one against a range twin, finishing it with every outcome derived
// from the server's own records, and reading the results. Storage is a port,
// so the rules run without a database.
package app

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/campaigns/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	"github.com/katocxl/pantherclaw/internal/redteam/library"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Limits.
const (
	MaxCampaigns    = 10
	MaxRoutes       = 64
	maxRunnerLength = 64
	maxLocator      = 512
)

var (
	idPattern     = regexp.MustCompile(`^RT-14[0-9]$`)
	digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	imagePattern  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	hostPattern   = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)
)

// Errors of the campaign use cases.
var (
	ErrEdition      = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED", "attack campaigns need a Business licence")
	ErrNotFound     = pcerr.New(pcerr.NotFound, "CAMPAIGN_NOT_FOUND", "campaign not found")
	ErrAgentMissing = pcerr.New(pcerr.NotFound, "AGENT_NOT_FOUND", "agent not found")
	ErrNotRange     = pcerr.New(pcerr.FailedPrecondition, "NOT_A_RANGE_AGENT", "a campaign runs only against a range twin, never a real agent")
	ErrRelay        = pcerr.New(pcerr.FailedPrecondition, "CAMPAIGN_RELAY_INVALID", "the relay must be a simulated connection")
	ErrOpen         = pcerr.New(pcerr.AlreadyExists, "CAMPAIGN_OPEN", "this range agent already has an open campaign")
	ErrNotRunning   = pcerr.New(pcerr.FailedPrecondition, "CAMPAIGN_NOT_RUNNING", "the campaign has finished or was abandoned")
	ErrScenarios    = pcerr.New(pcerr.InvalidArgument, "INVALID_CAMPAIGNS", "declare 1 to 10 distinct library campaigns, with an image digest and a model host")
	ErrNotLibrary   = pcerr.New(pcerr.InvalidArgument, "CAMPAIGN_NOT_LIBRARY", "a campaign must be the PantherClaw library's, with its digest")
	ErrRuns         = pcerr.New(pcerr.InvalidArgument, "INVALID_CAMPAIGN_RUNS", "each run is one declared campaign's, at most once, with at most 64 printable routes")
	// ErrRecord never says which rule failed, so it cannot be used to probe
	// other objects.
	ErrRecord = pcerr.New(pcerr.InvalidArgument, "CAMPAIGN_RECORD_INVALID", "a run named here is not a simulated run of this campaign's agent made after it started")
)

// AgentRef is an agent as campaigns need it.
type AgentRef struct {
	ID         ids.UUID
	RangeAgent bool
	Path       td.Path
}

// ConnectionRef is a connection as a campaign's relay.
type ConnectionRef struct {
	ID        ids.UUID
	Simulated bool
}

// Usage is a run's model traffic: counts and the host, never content (D313).
type Usage struct {
	Run            ids.UUID
	Scenario       string
	ModelHost      string
	Requests       int64
	BytesToModel   int64
	BytesFromModel int64
}

// Tx is the campaign store inside one tenant transaction.
type Tx interface {
	Agent(ctx context.Context, id ids.UUID) (AgentRef, error)
	Connection(ctx context.Context, id ids.UUID) (ConnectionRef, bool, error)
	// Campaign returns the campaign (locked for update when lock), or
	// ErrNotFound.
	Campaign(ctx context.Context, id ids.UUID, lock bool) (domain.Campaign, error)
	// OpenOf reports the range agent's open campaign, if any.
	OpenOf(ctx context.Context, agent ids.UUID) (domain.Campaign, bool, error)
	// InsertCampaign stores the campaign and returns it with the database's
	// start time.
	InsertCampaign(ctx context.Context, c domain.Campaign) (domain.Campaign, error)
	// Transition moves a campaign from Running and returns the database's
	// finish time; false when it no longer ran.
	Transition(ctx context.Context, id ids.UUID, to domain.State) (time.Time, bool, error)
	List(ctx context.Context, agent *ids.UUID, after ids.UUID, limit int32) ([]domain.Campaign, error)
	// CountsOf counts stored steps by campaign.
	CountsOf(ctx context.Context, campaigns []ids.UUID) (map[ids.UUID]domain.Counts, error)
	Steps(ctx context.Context, campaign ids.UUID) ([]domain.Step, error)
	InsertStep(ctx context.Context, campaign ids.UUID, s domain.Step) error
	Run(ctx context.Context, id ids.UUID) (domain.RunRecord, bool, error)
	Transactions(ctx context.Context, run ids.UUID) ([]domain.Transaction, error)
	// SetRunScenario records whose run it was.
	SetRunScenario(ctx context.Context, c domain.Campaign, run ids.UUID, scenario string) error
	Usage(ctx context.Context, campaign ids.UUID) ([]Usage, error)
	Audit(ctx context.Context, ev audit.Event) error
}

// Store runs fn in a tenant transaction for org.
type Store interface {
	InTx(ctx context.Context, org ids.OrgID, readOnly bool, fn func(ctx context.Context, tx Tx) error) error
}

// Editions reports the licence's entitlements.
type Editions interface {
	Current(ctx context.Context) (billing.Entitlements, error)
}

// Lookup returns a library campaign by id.
type Lookup func(id string) (library.CampaignEntry, bool)

// Service serves campaigns.
type Service struct {
	Store    Store
	Editions Editions
	// Library is library.Campaign unless a test sets it.
	Library Lookup
}

func (s *Service) lookup(id string) (library.CampaignEntry, bool) {
	if s.Library != nil {
		return s.Library(id)
	}
	return library.Campaign(id)
}

func (s *Service) entitlements(ctx context.Context) (billing.Entitlements, error) {
	if s.Editions == nil {
		return billing.CommunityEntitlements(), nil
	}
	return s.Editions.Current(ctx)
}

// Decl names a library campaign.
type Decl struct{ ID, Digest string }

// StartInput starts a campaign.
type StartInput struct {
	Agent         ids.UUID
	Campaigns     []Decl
	RunnerVersion string
	ImageDigest   string
	ModelHost     string
	Relay         ids.UUID
	Scripted      bool
}

func (s *Service) declared(in []Decl) ([]domain.Declared, error) {
	if len(in) == 0 || len(in) > MaxCampaigns {
		return nil, ErrScenarios
	}
	out := make([]domain.Declared, 0, len(in))
	seen := map[string]bool{}
	for _, d := range in {
		if seen[d.ID] || !idPattern.MatchString(d.ID) || !digestPattern.MatchString(d.Digest) {
			return nil, ErrScenarios
		}
		seen[d.ID] = true
		e, ok := s.lookup(d.ID)
		if !ok || e.Digest != d.Digest {
			return nil, ErrNotLibrary
		}
		out = append(out, domain.Declared{ID: d.ID, Digest: d.Digest, Attempts: e.Attempts})
	}
	return out, nil
}

// StartCampaign records a campaign against a range twin (redteam.run over the
// agent; Business). A real agent is refused here and by the database.
func (s *Service) StartCampaign(ctx context.Context, in StartInput) (domain.Campaign, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return domain.Campaign{}, err
	}
	if in.RunnerVersion == "" || len(in.RunnerVersion) > maxRunnerLength || !imagePattern.MatchString(in.ImageDigest) || !hostPattern.MatchString(in.ModelHost) {
		return domain.Campaign{}, ErrScenarios
	}
	decls, err := s.declared(in.Campaigns)
	if err != nil {
		return domain.Campaign{}, err
	}
	ents, err := s.entitlements(ctx)
	if err != nil {
		return domain.Campaign{}, err
	}
	if !ents.AgentCampaigns() {
		return domain.Campaign{}, ErrEdition
	}
	var out domain.Campaign
	err = s.Store.InTx(ctx, c.Org, false, func(ctx context.Context, tx Tx) error {
		a, err := agentFor(ctx, c, tx, in.Agent)
		if err != nil {
			return err
		}
		if !a.RangeAgent {
			return ErrNotRange
		}
		conn, found, err := tx.Connection(ctx, in.Relay)
		if err != nil {
			return err
		}
		if !found || !conn.Simulated {
			return ErrRelay
		}
		if _, open, err := tx.OpenOf(ctx, a.ID); err != nil {
			return err
		} else if open {
			return ErrOpen
		}
		names := make([]string, len(decls))
		for i, d := range decls {
			names[i] = d.ID
		}
		slices.Sort(names)
		out, err = tx.InsertCampaign(ctx, domain.Campaign{
			ID: ids.NewV7(), Agent: a.ID, StartedBy: c.Principal.String(), RunnerVersion: in.RunnerVersion, SetDigest: domain.SetDigest(decls),
			Scenarios: names, ImageDigest: in.ImageDigest, ModelHost: in.ModelHost, Relay: in.Relay, Scripted: in.Scripted, State: domain.Running,
		})
		if err != nil {
			return err
		}
		return tx.Audit(ctx, audit.Event{
			Name: "redteam.campaign_started", Actor: c.Actor(), Outcome: audit.Success,
			Object: &audit.Object{Type: "redteam_campaign", ID: out.ID.String()},
			Details: map[string]string{
				"agent_id": a.ID.String(), "campaigns": strings.Join(names, ","), "image_digest": in.ImageDigest, "model_host": in.ModelHost,
				"scripted": strconv.FormatBool(in.Scripted),
			},
		})
	})
	return out, err
}

func agentFor(ctx context.Context, c tenancy.Caller, tx Tx, id ids.UUID) (AgentRef, error) {
	a, err := tx.Agent(ctx, id)
	if err != nil {
		return a, err
	}
	if err := c.Require(td.PermRedteamRun, a.Path); err != nil {
		if c.Require(td.PermAgentRead, a.Path) != nil {
			return a, ErrAgentMissing
		}
		return a, err
	}
	return a, nil
}

// RunReport says whose run a run was and what its edge saw. It claims no
// outcome.
type RunReport struct {
	Scenario string
	Run      ids.UUID
	Routes   []domain.Route
}

// Detail is a campaign with its steps.
type Detail struct {
	Campaign domain.Campaign
	Steps    []domain.Step
	Counts   domain.Counts
	Usage    []Usage
}

func checkRuns(c domain.Campaign, runs []RunReport) error {
	if len(runs) > MaxCampaigns {
		return ErrRuns
	}
	seenRun, seenScenario := map[ids.UUID]bool{}, map[string]bool{}
	for _, r := range runs {
		if seenRun[r.Run] || seenScenario[r.Scenario] || !slices.Contains(c.Scenarios, r.Scenario) || len(r.Routes) > MaxRoutes {
			return ErrRuns
		}
		seenRun[r.Run], seenScenario[r.Scenario] = true, true
		for _, rt := range r.Routes {
			if (rt.Kind != domain.RouteDirectAPI && rt.Kind != domain.RouteCredential) || rt.Locator == "" || len(rt.Locator) > maxLocator {
				return ErrRuns
			}
		}
	}
	return nil
}

// FinishCampaign ends a running campaign (redteam.run) and derives every
// attempt's outcome. A scenario with no run has all its attempts
// NOT_EXERCISED, so leaving a run out can only widen the gap. The state
// change is conditional on the campaign still running, which closes the
// model route (D313).
func (s *Service) FinishCampaign(ctx context.Context, id ids.UUID, runs []RunReport) (Detail, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Detail{}, err
	}
	var out Detail
	err = s.Store.InTx(ctx, c.Org, false, func(ctx context.Context, tx Tx) error {
		cp, err := tx.Campaign(ctx, id, true)
		if err != nil {
			return err
		}
		if err := campaignAgentFor(ctx, c, tx, cp); err != nil {
			return err
		}
		if cp.State != domain.Running {
			return ErrNotRunning
		}
		if err := checkRuns(cp, runs); err != nil {
			return err
		}
		byScenario := map[string]RunReport{}
		for _, r := range runs {
			rec, found, err := tx.Run(ctx, r.Run)
			if err != nil {
				return err
			}
			if !found || !rec.Belongs(cp.Agent, cp.Started) {
				return ErrRecord
			}
			byScenario[r.Scenario] = r
		}
		now, ok, err := tx.Transition(ctx, cp.ID, domain.Finished)
		if err != nil {
			return err
		} else if !ok {
			return ErrNotRunning
		}
		cp.State, cp.Finished = domain.Finished, &now
		var steps []domain.Step
		for _, scenario := range cp.Scenarios {
			e, found := s.lookup(scenario)
			if !found {
				return ErrNotLibrary // a campaign started on another build
			}
			var txns []domain.Transaction
			r, ran := byScenario[scenario]
			if ran {
				if txns, err = tx.Transactions(ctx, r.Run); err != nil {
					return err
				}
				if err := tx.SetRunScenario(ctx, cp, r.Run, scenario); err != nil {
					return err
				}
			}
			for _, a := range e.Attempts {
				st := domain.Derive(scenario, a, txns, r.Routes)
				if err := tx.InsertStep(ctx, cp.ID, st); err != nil {
					return err
				}
				steps = append(steps, st)
			}
		}
		out = Detail{Campaign: cp, Steps: steps, Counts: domain.Count(steps)}
		return tx.Audit(ctx, audit.Event{
			Name: "redteam.campaign_finished", Actor: c.Actor(), Outcome: audit.Success,
			Object: &audit.Object{Type: "redteam_campaign", ID: cp.ID.String()},
			Details: map[string]string{
				"held": strconv.Itoa(out.Counts.Held), "denied": strconv.Itoa(out.Counts.Denied), "not_routed_reported": strconv.Itoa(out.Counts.NotRoutedReported),
				"allowed": strconv.Itoa(out.Counts.Allowed), "not_exercised": strconv.Itoa(out.Counts.NotExercised),
			},
		})
	})
	return out, err
}

func campaignAgentFor(ctx context.Context, c tenancy.Caller, tx Tx, cp domain.Campaign) error {
	a, err := tx.Agent(ctx, cp.Agent)
	if err != nil {
		if errors.Is(err, ErrAgentMissing) {
			return ErrNotFound
		}
		return err
	}
	if err := c.Require(td.PermRedteamRun, a.Path); err != nil {
		if c.Require(td.PermRedteamRead, a.Path) != nil {
			return ErrNotFound
		}
		return err
	}
	return nil
}

func readable(ctx context.Context, c tenancy.Caller, tx Tx, agent ids.UUID) error {
	a, err := tx.Agent(ctx, agent)
	if err != nil {
		if errors.Is(err, ErrAgentMissing) {
			return ErrNotFound
		}
		return err
	}
	if c.Require(td.PermRedteamRead, a.Path) != nil {
		return ErrNotFound
	}
	return nil
}

// GetCampaign returns a campaign, its steps and its model usage (redteam.read
// over its agent).
func (s *Service) GetCampaign(ctx context.Context, id ids.UUID) (Detail, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Detail{}, err
	}
	var out Detail
	err = s.Store.InTx(ctx, c.Org, true, func(ctx context.Context, tx Tx) error {
		cp, err := tx.Campaign(ctx, id, false)
		if err != nil {
			return err
		}
		if err := readable(ctx, c, tx, cp.Agent); err != nil {
			return err
		}
		steps, err := tx.Steps(ctx, cp.ID)
		if err != nil {
			return err
		}
		usage, err := tx.Usage(ctx, cp.ID)
		if err != nil {
			return err
		}
		out = Detail{Campaign: cp, Steps: steps, Counts: domain.Count(steps), Usage: usage}
		return nil
	})
	return out, err
}

// Page is one page of campaigns, newest first.
type Page struct {
	Items  []domain.Campaign
	Next   string
	Counts map[ids.UUID]domain.Counts
}

// ListCampaigns lists the campaigns whose agents the caller reads
// (redteam.read).
func (s *Service) ListCampaigns(ctx context.Context, agent *ids.UUID, pr page.Request) (Page, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Page{}, err
	}
	if !c.CanAnywhere(td.PermRedteamRead) {
		return Page{}, td.ErrPermissionDenied(td.PermRedteamRead)
	}
	var out Page
	err = s.Store.InTx(ctx, c.Org, true, func(ctx context.Context, tx Tx) error {
		after := pr.After
		var visible []domain.Campaign
		for len(visible) < pr.Size+1 {
			rows, err := tx.List(ctx, agent, after, pr.Limit())
			if err != nil {
				return err
			}
			for _, r := range rows {
				if readable(ctx, c, tx, r.Agent) == nil {
					visible = append(visible, r)
				}
			}
			if len(rows) < int(pr.Limit()) {
				break
			}
			after = rows[len(rows)-1].ID
		}
		out.Items, out.Next = page.Finish(pr, visible, func(r domain.Campaign) ids.UUID { return r.ID })
		listed := make([]ids.UUID, len(out.Items))
		for i, r := range out.Items {
			listed[i] = r.ID
		}
		var err error
		out.Counts, err = tx.CountsOf(ctx, listed)
		return err
	})
	return out, err
}
