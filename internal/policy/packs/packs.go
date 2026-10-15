// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package packs holds the reference workflow packs (G0 M11 part 2,
// coordinator decision D41; F762, F764, F767, HR-291): coding-to-production
// (GitHub) and read-only-diagnostics (shell). A pack is an M11.1 policy
// template (rules and its allow, hold and deny scenario tests), a grant
// baseline per agent and, optionally, the automation template that
// launches its agents.
//
// Applying a pack only drafts: it renders the template for the environment
// and agents, merges its rules and tests into the published policy and
// stores the result as a new DRAFT policy version through the policy
// versions API (policy.author), so it goes through validation, tests and
// the publish gate like any other draft. Nothing is published, no grant is
// issued and no agent is promoted; the baselines are returned for a person
// to issue from.
package packs

import (
	"context"
	"embed"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"

	aapp "github.com/katocxl/pantherclaw/internal/agents/app"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/cohorts"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	policyapp "github.com/katocxl/pantherclaw/internal/policy/app"
	"github.com/katocxl/pantherclaw/internal/policy/packs/render"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

//go:embed */pack.json
var packFS embed.FS

// Pack is one reference pack.
type Pack struct {
	Name    string `json:"name"`
	Summary string `json:"summary"`
	// Template is the policy template (templates/) the pack applies.
	Template           string   `json:"template"`
	BaselineTTLSeconds int      `json:"baseline_ttl_seconds"`
	AutomationTemplate string   `json:"automation_template,omitzero"`
	Covers             []string `json:"covers"`
	// Placeholders are the template's (read from it, not the pack file).
	Placeholders map[string]render.Spec `json:"-"`
}

// Parameters are what the template needs beyond the environment and the
// agents: the parameter names a pack lists in Placeholders.
const (
	ParamRepos         = "repos"
	ParamDefaultBranch = "default_branch"
	ParamWorkspace     = "workspace"
	ParamTimeZone      = "time_zone"
)

// paramNames name each placeholder kind's value in errors.
var paramNames = map[string]string{
	render.KindRepository: ParamRepos, render.KindDefaultBranch: ParamDefaultBranch, render.KindEnvironment: "environment",
	render.KindEnvironmentID: "environment", render.KindWorkspace: ParamWorkspace, render.KindAgent: "agents",
	render.KindTimeZone: ParamTimeZone,
}

const (
	maxAgents  = 50
	maxBundles = 512
)

// Errors.
var (
	ErrNotFound       = pcerr.New(pcerr.NotFound, "PACK_NOT_FOUND", "no such pack")
	ErrEdition        = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED", "reference packs need the Team edition")
	ErrEnvironment    = pcerr.New(pcerr.NotFound, "ENVIRONMENT_NOT_FOUND", "environment not found")
	ErrAgentNotFound  = pcerr.New(pcerr.NotFound, "AGENT_NOT_FOUND", "agent not found")
	ErrAgentElsewhere = pcerr.New(pcerr.FailedPrecondition, "AGENT_IN_ANOTHER_ENVIRONMENT", "an agent works in another environment")
	ErrHumanOnly      = pcerr.New(pcerr.PermissionDenied, "HUMAN_ONLY", "only a person signed in as themselves can apply a pack")
)

func invalid(format string, args ...any) error {
	return pcerr.New(pcerr.InvalidArgument, "INVALID_PACK_PARAMETERS", fmt.Sprintf(format, args...))
}

// List returns every pack, by name.
func List() ([]Pack, error) {
	entries, err := fs.ReadDir(packFS, ".")
	if err != nil {
		return nil, err
	}
	var out []Pack
	for _, e := range entries {
		if e.IsDir() {
			p, err := Get(e.Name())
			if err != nil {
				return nil, err
			}
			out = append(out, p)
		}
	}
	return out, nil
}

// Get returns one pack.
func Get(name string) (Pack, error) {
	var p Pack
	raw, err := fs.ReadFile(packFS, name+"/pack.json")
	if err != nil || strings.ContainsAny(name, "/\\.") {
		return p, ErrNotFound
	}
	if err := json.Unmarshal(raw, &p, json.RejectUnknownMembers(true)); err != nil {
		return p, fmt.Errorf("packs: %s: %w", name, err)
	}
	info, err := render.ReadInfo(p.Template)
	if err != nil {
		return p, fmt.Errorf("packs: %s: %w", name, err)
	}
	p.Placeholders = info.Placeholders
	return p, nil
}

// Needs lists the parameters a pack needs, sorted.
func (p Pack) Needs() []string {
	var out []string
	for kind := range p.Placeholders {
		switch kind {
		case render.KindRepository:
			out = append(out, ParamRepos, ParamDefaultBranch)
		case render.KindWorkspace:
			out = append(out, ParamWorkspace)
		case render.KindTimeZone:
			out = append(out, ParamTimeZone)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// Editions reports the licence's entitlements.
type Editions interface {
	Current(ctx context.Context) (billing.Entitlements, error)
}

// Drafts is the policy versions API a pack drafts through (policy.author
// and policy.read are checked there).
type Drafts interface {
	Published(ctx context.Context) (*policyapp.VersionInfo, error)
	CreateExpecting(ctx context.Context, raw []byte, expected *ids.UUID) (policyapp.VersionInfo, error)
}

// Service applies packs.
type Service struct {
	Pool     *db.Pool
	Editions Editions
	Drafts   Drafts
}

// Apply asks to apply a pack in an environment for agents (or a cohort's).
type Apply struct {
	Pack        string
	Environment ids.UUID
	Agents      []ids.UUID
	Cohort      *ids.UUID
	// Parameters: repos (comma-separated owner/repo), default_branch (a
	// branch, or owner/repo=branch entries, comma-separated), workspace,
	// time_zone.
	Parameters map[string]string
}

// Baseline is the grant a person may issue an agent from the pack.
type Baseline struct {
	Agent      ids.UUID
	TaskRef    string
	Bounds     []byte
	Limits     []byte
	TTLSeconds int
}

// Applied is the draft a pack made.
type Applied struct {
	Pack    Pack
	Version policyapp.VersionInfo
	// Added and Replaced are the rule and test ids the draft adds to, or
	// changes in, the published policy; Unchanged are already there as the
	// pack has them.
	Added, Replaced, Unchanged []string
	// Skipped are agent rules left out because no agent was named.
	Skipped   []string
	Baselines []Baseline
}

func (s *Service) team(ctx context.Context) error {
	if s.Editions == nil {
		return ErrEdition
	}
	e, err := s.Editions.Current(ctx)
	if err != nil {
		return err
	}
	if !e.Edition.Paid() {
		return ErrEdition
	}
	return nil
}

// ApplyPack renders a pack for an environment and agents and stores the
// published policy with its rules and tests as a new DRAFT version
// (policy.author; Team). Nothing is published or issued (HR-291).
func (s *Service) ApplyPack(ctx context.Context, in Apply) (Applied, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return Applied{}, err
	}
	if !c.Human() || c.Credential == tapp.CredAPIKey {
		return Applied{}, ErrHumanOnly
	}
	if err := c.Require(policyapp.PermPolicyAuthor, td.OrgPath(c.Org)); err != nil {
		return Applied{}, err
	}
	if err := s.team(ctx); err != nil {
		return Applied{}, err
	}
	p, err := Get(in.Pack)
	if err != nil {
		return Applied{}, err
	}
	base, err := p.options(in.Parameters)
	if err != nil {
		return Applied{}, err
	}
	agents, err := s.target(ctx, c, &base, in)
	if err != nil {
		return Applied{}, err
	}
	out := Applied{Pack: p}
	rules, tests := map[string]map[string]any{}, map[string]map[string]any{}
	var order []string
	renders := []render.Options{base}
	if len(agents) > 0 {
		renders = renders[:0]
		for _, a := range agents {
			o := base
			o.Agent = a.String()
			renders = append(renders, o)
		}
	}
	for i, o := range renders {
		d, err := render.Render(o)
		if err != nil {
			return Applied{}, invalid("%v", err)
		}
		for _, r := range d.Rules {
			id, _ := r["id"].(string)
			if _, ok := rules[id]; !ok {
				order = append(order, "rule:"+id)
			}
			rules[id] = r
		}
		for _, t := range d.Tests {
			id, _ := t["id"].(string)
			if _, ok := tests[id]; !ok {
				order = append(order, "test:"+id)
			}
			tests[id] = t
		}
		if i == 0 {
			out.Skipped = d.Skipped
		}
		if o.Agent != "" {
			agent, _ := ids.ParseUUID(o.Agent)
			out.Baselines = append(out.Baselines, Baseline{
				Agent: agent, TaskRef: d.TaskRef, Bounds: d.Grant.Bounds, Limits: d.Grant.Limits, TTLSeconds: p.BaselineTTLSeconds,
			})
		}
	}
	pub, err := s.Drafts.Published(ctx)
	if err != nil {
		return Applied{}, err
	}
	bundle := map[string]any{"id": p.Name}
	expected := ids.UUID{}
	if pub != nil {
		if err := json.Unmarshal(pub.Bundle, &bundle); err != nil {
			return Applied{}, err
		}
		expected = pub.ID
	}
	delete(bundle, "version")
	merge := func(key string, items map[string]map[string]any, kind string) error {
		list, _ := bundle[key].([]any)
		for _, id := range order {
			k, name, _ := strings.Cut(id, ":")
			if k != kind {
				continue
			}
			want := items[name]
			at := slices.IndexFunc(list, func(x any) bool { m, _ := x.(map[string]any); return m["id"] == name })
			switch {
			case at < 0:
				list = append(list, want)
				out.Added = append(out.Added, name)
			case sameJSON(list[at], want):
				out.Unchanged = append(out.Unchanged, name)
			default:
				list[at] = want
				out.Replaced = append(out.Replaced, name)
			}
		}
		if len(list) > maxBundles {
			return invalid("the draft would hold more than %d %ss", maxBundles, kind)
		}
		bundle[key] = list
		return nil
	}
	if err := errors.Join(merge("rules", rules, "rule"), merge("tests", tests, "test")); err != nil {
		return Applied{}, err
	}
	raw, err := json.Marshal(bundle, json.Deterministic(true))
	if err != nil {
		return Applied{}, err
	}
	if out.Version, err = s.Drafts.CreateExpecting(ctx, raw, &expected); err != nil {
		return Applied{}, err
	}
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := audit.Record(ctx, tx, audit.Event{
			Name: "policy.pack_applied", Actor: c.Actor(), Outcome: audit.Success,
			Object: &audit.Object{Type: "policy_version", ID: out.Version.ID.String()},
			Details: map[string]string{
				"pack": p.Name, "environment": in.Environment.String(), "agents": fmt.Sprint(len(agents)),
				"added": fmt.Sprint(len(out.Added)), "replaced": fmt.Sprint(len(out.Replaced)),
			},
		})
		return err
	})
	return out, err
}

func sameJSON(a, b any) bool {
	x, err1 := json.Marshal(a, json.Deterministic(true))
	y, err2 := json.Marshal(b, json.Deterministic(true))
	return err1 == nil && err2 == nil && string(x) == string(y)
}

// options turns a pack's parameters into render options; the template's
// own checks run when it is rendered.
func (p Pack) options(params map[string]string) (render.Options, error) {
	o := render.Options{Name: p.Template, Names: paramNames, Defaults: map[string]string{}}
	needs := p.Needs()
	for k := range params {
		if !slices.Contains(needs, k) {
			return o, invalid("pack %s takes no parameter %q (it takes %v)", p.Name, k, needs)
		}
	}
	for _, r := range strings.Split(params[ParamRepos], ",") {
		if r = strings.TrimSpace(r); r != "" && !slices.Contains(o.Repos, r) {
			o.Repos = append(o.Repos, r)
		}
	}
	slices.Sort(o.Repos)
	if slices.Contains(needs, ParamRepos) && len(o.Repos) == 0 {
		return o, invalid("pack %s needs repos", p.Name)
	}
	all := "main"
	for _, d := range strings.Split(params[ParamDefaultBranch], ",") {
		if d = strings.TrimSpace(d); d == "" {
			continue
		}
		repo, branch, one := strings.Cut(d, "=")
		switch {
		case !one:
			all = d
		case !slices.Contains(o.Repos, repo):
			return o, invalid("default_branch: %s is not among repos", repo)
		default:
			o.Defaults[repo] = branch
		}
	}
	for _, r := range o.Repos {
		if _, ok := o.Defaults[r]; !ok {
			o.Defaults[r] = all
		}
	}
	o.Workspace = params[ParamWorkspace]
	if slices.Contains(needs, ParamWorkspace) && o.Workspace == "" {
		return o, invalid("pack %s needs workspace", p.Name)
	}
	o.TimeZone = params[ParamTimeZone]
	if o.TimeZone == "" {
		o.TimeZone = "UTC"
	}
	return o, nil
}

// target resolves the environment (its slug and id go into the template)
// and the agents: those named, or a cohort's; each must be one the caller
// may read and work in the environment.
func (s *Service) target(ctx context.Context, c tapp.Caller, o *render.Options, in Apply) ([]ids.UUID, error) {
	if len(in.Agents) > 0 && in.Cohort != nil {
		return nil, invalid("name agents or a cohort, not both")
	}
	var agents []ids.UUID
	err := s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		env, err := q.GetEnvironment(ctx, c.Org, in.Environment)
		if db.IsNoRows(err) {
			return ErrEnvironment
		} else if err != nil {
			return err
		}
		o.Environment, o.EnvironmentID = env.Slug, env.ID.String()
		agents = slices.Clone(in.Agents)
		if in.Cohort != nil {
			if agents, err = cohorts.Resolve(ctx, tx, *in.Cohort, maxAgents+1); err != nil {
				return err
			}
		}
		if len(agents) > maxAgents {
			return invalid("at most %d agents", maxAgents)
		}
		for _, id := range agents {
			a, err := q.GetAgent(ctx, c.Org, id)
			if db.IsNoRows(err) {
				return ErrAgentNotFound
			} else if err != nil {
				return err
			}
			path, err := aapp.PathOf(ctx, q, a)
			if err != nil {
				return err
			}
			if !c.Can(td.PermAgentRead, path) {
				return ErrAgentNotFound
			}
			if a.EnvironmentID == nil || *a.EnvironmentID != env.ID {
				return ErrAgentElsewhere
			}
		}
		return nil
	}, db.ReadOnly())
	slices.SortFunc(agents, func(a, b ids.UUID) int { return strings.Compare(a.String(), b.String()) })
	return slices.Compact(agents), err
}
