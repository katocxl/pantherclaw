// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"maps"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/money"
	"github.com/katocxl/pantherclaw/internal/policy/packs/render"
)

// pclaw template apply (G0 M8 C4): a template is data in templates/, applied
// as a person through the server's existing APIs only, so every step is
// authorized and audited there as if the person had made it by hand. The
// plan comes first; a dry run changes nothing. Applying again changes
// nothing that is already as the template says; something that exists and
// differs is changed only with --update (the coordinator's decision,
// 2026-10-13), so weakening a guardrail or a rule is never silent.

func init() {
	commands["template apply"] = command{
		usage: "template apply NAME [--repos OWNER/REPO[,OWNER/REPO…]] [--workspace PATH] [--agent ID] [--team ID | --bu ID] [--environment NAME] " +
			"[--time-zone TZ] [--default-branch BRANCH | --default-branch OWNER/REPO=BRANCH]… [--expires DURATION] [--dry-run] [--update] [--yes]",
		run: templateApply,
	}
}

// templateOptions are what a template is applied with.
type templateOptions struct {
	name  string
	repos []string
	// lists are the list kinds' values (render.ListKinds): payees,
	// customers, Slack channels.
	lists                 map[string][]string
	defaults              map[string]string // repository → default branch
	agent, team, bu       string
	environment, timeZone string
	// workspace is the directory a template's shell rules confine
	// commands to; environmentID is --environment's id, resolved from
	// the server when the template needs it.
	workspace, environmentID string
	expires                  time.Duration
	dryRun, update, yes      bool
	// planOnly, set by init --yes without --yes-template, shows the plan
	// and applies nothing.
	planOnly bool
}

var (
	templateNameRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	// templateRepoRe is a GitHub repository as pc.github names targets.
	templateRepoRe   = render.RepoRe
	templateBranchRe = render.BranchRe
	uuidRe           = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// templateNeeds are the permissions each plan step's changes need, in
// plan order: the policy, the window, the envelope and the grant. They are
// checked before anything is changed. The check reads permissions held
// anywhere in the org, not at a scope, so a step can still be refused: the
// steps that protect come first and the grant last, so a refusal never
// leaves a grant without its rules.
var templateNeeds = [][]string{
	{"policy.author", "policy.publish"},
	{"release.window.manage"},
	{"guardrails.manage"},
	{"grant.issue"},
}

// errTemplateDiffers: something the template would change exists already
// and differs; nothing was changed.
var errTemplateDiffers = errors.New("what exists differs from the template (shown above); nothing was changed. Pass --update to change it")

// templateFlags parses the options; init passes its own agent.
func templateFlags(fs *flag.FlagSet, o *templateOptions) func() error {
	repos := fs.String("repos", "", "the GitHub repositories, owner/repo, comma-separated")
	var defaults multi
	fs.Var(&defaults, "default-branch", "the default branch to protect (main), or OWNER/REPO=BRANCH for one repository (repeatable)")
	lists := map[string]*multi{}
	for kind, usage := range map[string]string{
		render.KindPayee:        "a Stripe connected account, acct_..., the template may send funds to (repeatable)",
		render.KindCustomer:     "a customer whose records the template's grant may read (repeatable)",
		render.KindSlackChannel: "a Slack channel id, C... or G..., the template may post to (repeatable; required by templates that post)",
	} {
		lists[kind] = &multi{}
		fs.Var(lists[kind], strings.TrimPrefix(render.Flags[kind], "--"), usage)
	}
	fs.StringVar(&o.team, "team", "", "bound the grants of this team's agents to the repositories (a guardrail envelope)")
	fs.StringVar(&o.bu, "bu", "", "bound the grants of this business unit's agents to the repositories (a guardrail envelope)")
	fs.StringVar(&o.environment, "environment", "production", "the environment the template's rules and change window are for (its slug)")
	fs.StringVar(&o.workspace, "workspace", "", "the workspace directory the template's shell rules confine commands to (an absolute path)")
	fs.StringVar(&o.timeZone, "time-zone", "UTC", "the change window's time zone")
	fs.DurationVar(&o.expires, "expires", 30*24*time.Hour, "how long the agent's grant lasts")
	return func() error {
		info, err := readTemplateInfo(o.name)
		if err != nil {
			return err
		}
		has := func(kind string) bool { _, ok := info.Placeholders[kind]; return ok }
		for _, r := range strings.Split(*repos, ",") {
			if r = strings.TrimSpace(r); r == "" {
				continue
			}
			if !templateRepoRe.MatchString(r) {
				return fmt.Errorf("--repos: %q is not a lowercase owner/repo", r)
			}
			if !slices.Contains(o.repos, r) {
				o.repos = append(o.repos, r)
			}
		}
		o.lists = map[string][]string{}
		for _, kind := range slices.Sorted(maps.Keys(render.ListKinds)) {
			lk, flagName := render.ListKinds[kind], render.Flags[kind]
			var values []string
			for _, v := range *lists[kind] {
				if !lk.Re.MatchString(v) || v == lk.Other {
					return fmt.Errorf("%s: %q is not %s", flagName, v, lk.What)
				}
				if !slices.Contains(values, v) {
					values = append(values, v)
				}
			}
			slices.Sort(values)
			switch {
			case has(kind) && len(values) == 0:
				return fmt.Errorf("template %s needs %s", o.name, flagName)
			case !has(kind) && len(values) > 0:
				return fmt.Errorf("template %s takes no %s", o.name, flagName)
			}
			o.lists[kind] = values
		}
		switch {
		case has(kindRepository) && len(o.repos) == 0:
			return errors.New("--repos names no repository")
		case !has(kindRepository) && len(o.repos) > 0:
			return fmt.Errorf("template %s takes no --repos", o.name)
		case !has(kindDefaultBranch) && len(defaults) > 0:
			return fmt.Errorf("template %s takes no --default-branch", o.name)
		case has(kindWorkspace) && o.workspace == "":
			return fmt.Errorf("template %s needs --workspace", o.name)
		case !has(kindWorkspace) && o.workspace != "":
			return fmt.Errorf("template %s takes no --workspace", o.name)
		}
		slices.Sort(o.repos)
		o.defaults = map[string]string{}
		all := "main"
		for _, d := range defaults {
			repo, branch, one := strings.Cut(d, "=")
			if !one {
				repo, branch = "", d
			}
			switch {
			case !templateBranchRe.MatchString(branch):
				return fmt.Errorf("--default-branch: %q is not a branch name", branch)
			case !one:
				all = branch
			case !slices.Contains(o.repos, repo):
				return fmt.Errorf("--default-branch: %s is not among --repos", repo)
			default:
				o.defaults[repo] = branch
			}
		}
		for _, r := range o.repos {
			if _, ok := o.defaults[r]; !ok {
				o.defaults[r] = all
			}
		}
		for name, id := range map[string]string{"--agent": o.agent, "--team": o.team, "--bu": o.bu} {
			if id != "" && !uuidRe.MatchString(id) {
				return fmt.Errorf("%s: %q is not an id", name, id)
			}
		}
		if info.RequiresAgent && o.agent == "" {
			return fmt.Errorf("template %s needs --agent: its rules are the agent's", o.name)
		}
		if info.RequiresScope && o.team == "" && o.bu == "" {
			return fmt.Errorf("template %s needs --team or --bu: its weekly cap is that scope's envelope", o.name)
		}
		if o.team != "" && o.bu != "" {
			return errors.New("--team and --bu: give one scope")
		}
		if o.expires <= 0 {
			return errors.New("--expires must be positive")
		}
		return nil
	}
}

// multi is a repeatable string flag.
type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func templateApply(ctx context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("template apply", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	var o templateOptions
	fs.StringVar(&o.agent, "agent", "", "issue the template's grant to this agent")
	fs.BoolVar(&o.dryRun, "dry-run", false, "show the plan and change nothing")
	fs.BoolVar(&o.update, "update", false, "change what exists and differs from the template")
	fs.BoolVar(&o.yes, "yes", false, "apply without asking")
	check := templateFlags(fs, &o)
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return errUsage
	}
	o.name = args[0]
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
		return errUsage
	}
	if err := check(); err != nil {
		return err
	}
	return applyTemplate(ctx, a, o)
}

// sameJSON reports whether two JSON documents hold the same value.
func sameJSON(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}

// templateStep is one change the plan shows: what, and whether it is new,
// already as the template says, different, or skipped and why.
type templateStep struct {
	what, state string
	notes       []string
	apply       func(context.Context) (string, error)
	// bundle and planned are the policy step's new bundle and the version
	// it was planned from.
	bundle  map[string]any
	planned string
}

const (
	stepCreate    = "create"
	stepUnchanged = "unchanged"
	stepDiffers   = "differs"
	stepUpdate    = "update"
	stepSkipped   = "skipped"
)

func applyTemplate(ctx context.Context, a *app, o templateOptions) error {
	// The options are checked before anything is read from the server;
	// the environment's id comes from it.
	if _, err := renderTemplate(o); err != nil && !errors.Is(err, errNeedsEnvironmentID) {
		return err
	}
	c, err := a.clients()
	if err != nil {
		return err
	}
	me, err := c.access.WhoAmI(ctx, &pantherclawv1.WhoAmIRequest{})
	if err != nil {
		return err
	}
	if me.GetPrincipal().GetType() != pantherclawv1.PrincipalType_PRINCIPAL_TYPE_USER {
		return errors.New("a template is applied by a person, signed in with pclaw login")
	}
	if err := resolveEnvironment(ctx, c, &o); err != nil {
		return err
	}
	data, err := renderTemplate(o)
	if err != nil {
		return err
	}
	var steps []templateStep
	var missing []string
	for i, plan := range []func(context.Context, clients, templateOptions, templateData, string) (templateStep, error){
		planPolicy, planWindow, planEnvelope, planGrant,
	} {
		s, err := plan(ctx, c, o, data, me.GetPrincipal().GetId())
		if err != nil {
			return fmt.Errorf("planning the %s: %s (nothing was changed)", s.what, describe(err))
		}
		if s.state == stepDiffers && o.update {
			s.state = stepUpdate
		}
		if s.state == stepCreate || s.state == stepUpdate || s.state == stepDiffers {
			for _, p := range templateNeeds[i] {
				if !slices.Contains(me.GetPermissions(), p) && !slices.Contains(missing, p) {
					missing = append(missing, p)
				}
			}
		}
		steps = append(steps, s)
	}

	w := a.stdout
	if len(o.repos) > 0 {
		_, _ = fmt.Fprintf(w, "Template %s for %s, as %s:\n", o.name, strings.Join(o.repos, ", "), me.GetPrincipal().GetDisplayName())
	} else {
		_, _ = fmt.Fprintf(w, "Template %s, as %s:\n", o.name, me.GetPrincipal().GetDisplayName())
	}
	differs, changes := false, 0
	for _, s := range steps {
		_, _ = fmt.Fprintf(w, "  %-9s %s\n", s.state, s.what)
		for _, n := range s.notes {
			_, _ = fmt.Fprintf(w, "            %s\n", n)
		}
		switch s.state {
		case stepDiffers:
			differs = true
		case stepCreate, stepUpdate:
			changes++
		}
	}
	if _, ok := data.Info.Placeholders[kindDefaultBranch]; ok {
		for _, r := range o.repos {
			_, _ = fmt.Fprintf(w, "  Protects %s's default branch %s from writes; renaming a default branch needs this template applied again.\n", r, o.defaults[r])
		}
	}
	if roles := approvalRoles(data.Rules); len(roles) > 0 {
		_, _ = fmt.Fprintf(w, "  Binds no people to roles: bind %s yourself (pclaw role bind).\n", strings.Join(roles, " and "))
	}
	for _, warn := range monitorWarnings(ctx, c, data.Info) {
		_, _ = fmt.Fprintf(w, "  warning: %s\n", warn)
	}
	if len(missing) > 0 {
		_, _ = fmt.Fprintf(w, "  You lack %s, which these changes need; a person holding them applies the template (pclaw whoami).\n", strings.Join(missing, ", "))
	}
	switch {
	case differs:
		return errTemplateDiffers
	case len(missing) > 0 && !o.dryRun && !o.planOnly:
		return errors.New("you lack permissions these changes need (shown above); nothing was changed")
	case o.dryRun:
		_, _ = fmt.Fprintln(w, "Dry run: nothing was changed.")
		return nil
	case o.planOnly:
		_, _ = fmt.Fprintln(w, "Not applied: pass --yes-template to apply the template too.")
		return nil
	case changes == 0:
		_, _ = fmt.Fprintln(w, "Nothing to change: everything is as the template says.")
		return nil
	case !o.yes && !confirm(a, fmt.Sprintf("Make these %d change(s)?", changes)):
		return errors.New("nothing was changed")
	}
	for _, s := range steps {
		if s.state != stepCreate && s.state != stepUpdate {
			continue
		}
		done, err := s.apply(ctx)
		var wait *waitingError
		if errors.As(err, &wait) {
			// A loosening waits for confirmations (D6). The steps after the
			// policy, the grant last, wait with it, so no grant is issued
			// before its rules are in effect.
			_, _ = fmt.Fprintf(w, "Waiting for confirmation: %s\n", wait.msg)
			_, _ = fmt.Fprintln(w, "Run the command again once it is confirmed to make the remaining changes.")
			return nil
		}
		if err != nil {
			return fmt.Errorf("%s: %s (the steps before it were made)", s.what, describe(err))
		}
		_, _ = fmt.Fprintf(w, "Done: %s\n", done)
	}
	return nil
}

// planEnvelope bounds a team's or business unit's grants to the
// repositories; without a scope it is skipped, never org-wide.
func planEnvelope(ctx context.Context, c clients, o templateOptions, d templateData, _ string) (templateStep, error) {
	kind, id := pantherclawv1.GuardrailScopeKind_GUARDRAIL_SCOPE_KIND_TEAM, o.team
	if o.bu != "" {
		kind, id = pantherclawv1.GuardrailScopeKind_GUARDRAIL_SCOPE_KIND_BUSINESS_UNIT, o.bu
	}
	if !d.Envelope.Present {
		return templateStep{what: "guardrail envelope", state: stepSkipped, notes: []string{"the template sets no envelope"}}, nil
	}
	if id == "" {
		return templateStep{what: "guardrail envelope", state: stepSkipped, notes: []string{
			"warning: no envelope; pass --team (or --bu) to bound that team's grants to these repositories. The grant's own bounds hold either way.",
		}}, nil
	}
	s := templateStep{
		what:  fmt.Sprintf("guardrail envelope %q on %s %s", d.Envelope.Name, strings.ToLower(strings.TrimPrefix(kind.String(), "GUARDRAIL_SCOPE_KIND_")), id),
		notes: []string{"every grant of its agents is limited to the GitHub operations on these repositories"},
	}
	if d.Envelope.Limits != nil {
		s.notes = []string{"every grant of its agents shares the envelope's budgets: " + string(d.Envelope.Limits)}
	}
	var cur *pantherclawv1.Envelope
	for token := ""; ; {
		res, err := c.guardrails.ListEnvelopes(ctx, &pantherclawv1.ListEnvelopesRequest{PageSize: 200, PageToken: token, Kind: kind})
		if err != nil {
			return s, err
		}
		for _, e := range res.GetEnvelopes() {
			if e.GetScope().GetId() == id {
				cur = e
			}
		}
		if token = res.GetNextPageToken(); token == "" || cur != nil {
			break
		}
	}
	if cur == nil {
		s.state = stepCreate
		s.apply = func(ctx context.Context) (string, error) {
			res, err := c.guardrails.CreateEnvelope(ctx, &pantherclawv1.CreateEnvelopeRequest{
				Scope: &pantherclawv1.GuardrailScope{Kind: kind, Id: id}, Name: d.Envelope.Name, Bounds: d.Envelope.Bounds, Limits: d.Envelope.Limits,
			})
			return "guardrail envelope " + res.GetEnvelope().GetId() + " created", err
		}
		return s, nil
	}
	// A limits-only envelope (empty bounds, D120) keeps the scope's bounds
	// and adds its budgets to the scope's, by id: it never widens what
	// another template's envelope bounds.
	bounds, limits := d.Envelope.Bounds, d.Envelope.Limits
	if cur != nil && limits != nil && sameJSON(bounds, []byte("{}")) {
		bounds = cur.GetBounds()
		merged, loosened, kept, err := mergeBudgets(cur.GetLimits(), limits, o.update)
		if err != nil {
			return s, fmt.Errorf("guardrail envelope %s: %w", cur.GetId(), err)
		}
		limits = merged
		for _, l := range loosened {
			s.notes = append(s.notes, "LOOSENING: "+l)
		}
		for _, k := range kept {
			s.notes = append(s.notes, "warning: "+k)
		}
		if missing, err := uncovered(bounds, d.Grant.Bounds); err != nil {
			return s, fmt.Errorf("guardrail envelope %s: %w", cur.GetId(), err)
		} else if len(missing) > 0 {
			s.notes = append(s.notes, "warning: the scope's envelope bounds do not cover "+strings.Join(missing, ", ")+
				": the template's grants for this scope would be refused when issued")
		}
	}
	switch {
	case sameJSON(cur.GetBounds(), bounds) && (limits == nil || sameJSON(cur.GetLimits(), limits)):
		s.state = stepUnchanged
	default:
		s.state = stepDiffers
		s.notes = append(s.notes, "its bounds now: "+string(cur.GetBounds()), "the template's: "+string(bounds))
		if limits == nil {
			limits = cur.GetLimits()
		} else {
			s.notes = append(s.notes, "its limits now: "+string(cur.GetLimits()), "the template's: "+string(limits))
		}
		s.apply = func(ctx context.Context) (string, error) {
			res, err := c.guardrails.ReviseEnvelope(ctx, &pantherclawv1.ReviseEnvelopeRequest{
				Id: cur.GetId(), Revision: cur.GetRevision(), Name: cur.GetName(), Bounds: bounds,
				Requirements: cur.GetRequirements(), Limits: limits, Settings: cur.GetSettings(), MinAttestationLevel: cur.GetMinAttestationLevel(),
			})
			return fmt.Sprintf("guardrail envelope %s revised to %d", cur.GetId(), res.GetEnvelope().GetRevision()), err
		}
	}
	return s, nil
}

// mergeBudgets adds the template's budgets to an envelope's limits, by
// id, keeping every other budget and counter. Where the scope already has
// a budget of that id, the stricter one stays (D129 L2): a template budget
// that would raise or otherwise change it replaces it only with update,
// and is listed in loosened; without update it is not applied and is
// listed in kept, so the plan says so (D131).
func mergeBudgets(cur, tpl []byte, update bool) (merged []byte, loosened, kept []string, err error) {
	limits := map[string]any{}
	if len(cur) > 0 && string(cur) != "null" {
		if err := json.Unmarshal(cur, &limits); err != nil {
			return nil, nil, nil, fmt.Errorf("its limits: %w", err)
		}
	}
	var add struct {
		Budgets []map[string]any `json:"budgets"`
	}
	if err := json.Unmarshal(tpl, &add); err != nil {
		return nil, nil, nil, err
	}
	have, _ := limits["budgets"].([]any)
	for _, b := range add.Budgets {
		i := slices.IndexFunc(have, func(x any) bool { m, _ := x.(map[string]any); return m["id"] == b["id"] })
		switch {
		case i < 0:
			have = append(have, b)
		case notLooser(b, have[i]):
			have[i] = b
		case update:
			loosened = append(loosened, fmt.Sprintf("budget %v changes from %v to %v", b["id"], have[i], b))
			have[i] = b
		default:
			old, _ := json.Marshal(have[i], json.Deterministic(true))
			tplB, _ := json.Marshal(b, json.Deterministic(true))
			kept = append(kept, fmt.Sprintf("the template's budget %v is not applied: the scope's own budget with that id wins and is kept (%s; the template's: %s). "+
				"Pass --update to replace it, a loosening", b["id"], old, tplB))
		}
	}
	limits["budgets"] = have
	merged, err = json.Marshal(limits, json.Deterministic(true))
	return merged, loosened, kept, err
}

// notLooser reports whether budget b is the same as old except, at most,
// a lower limit or max_count.
func notLooser(b map[string]any, oldAny any) bool {
	old, _ := oldAny.(map[string]any)
	for _, k := range []string{"grouping", "operations", "currency", "period"} {
		if !sameJSONValue(b[k], old[k]) {
			return false
		}
	}
	for _, k := range []string{"limit", "max_count"} {
		nv, nok := b[k].(string)
		ov, ook := old[k].(string)
		switch {
		case !nok && !ook:
		case nok != ook:
			return nok // a new bound where there was none tightens; dropping one does not
		default:
			n, err1 := money.Parse(nv)
			o, err2 := money.Parse(ov)
			if err1 != nil || err2 != nil || n.Cmp(o) > 0 {
				return false
			}
		}
	}
	return true
}

func sameJSONValue(a, b any) bool {
	x, err1 := json.Marshal(a, json.Deterministic(true))
	y, err2 := json.Marshal(b, json.Deterministic(true))
	return err1 == nil && err2 == nil && string(x) == string(y)
}

// uncovered lists the template grant's operations that the envelope
// bounds leave out (D129 L1).
func uncovered(envBounds, grantBounds []byte) ([]string, error) {
	env, err := gdomain.DecodeBounds(envBounds)
	if err != nil {
		return nil, err
	}
	var grant struct {
		Operations []string `json:"operations"`
	}
	if err := json.Unmarshal(grantBounds, &grant); err != nil {
		return nil, err
	}
	var out []string
	for _, op := range grant.Operations {
		if env.Operations != nil && !env.Operations.Matches(op) {
			out = append(out, op)
		}
	}
	return out, nil
}

// planPolicy adds the template's rules and scenario tests to the published
// bundle, as a new version that goes through the publish gate (M11.1 D6):
// validated, tested, and published when it tightens the policy, or left
// waiting for confirmations when it loosens it.
func planPolicy(ctx context.Context, c clients, o templateOptions, d templateData, _ string) (templateStep, error) {
	s := templateStep{what: "policy rules " + ruleIDs(d.Rules)}
	bundle, planned, err := publishedBundle(ctx, c)
	if err != nil {
		return s, err
	}
	// A rule over every repository ({{repos}}) keeps the repositories the
	// template was applied for before.
	if len(d.ReposItems) > 0 && !o.update {
		applied, err := appliedRepos(bundle, o, d)
		if err != nil {
			return s, err
		}
		if all := union(applied, o.repos); !slices.Equal(all, o.repos) {
			wide := o
			wide.repos = all
			if d, err = renderOver(d, wide); err != nil {
				return s, err
			}
		}
	}
	rules, _ := bundle["rules"].([]any)
	tests, _ := bundle["tests"].([]any)
	var added, changed int
	merge := func(have []any, want []map[string]any, what string) []any {
		for _, w := range want {
			i := slices.IndexFunc(have, func(r any) bool { m, _ := r.(map[string]any); return m["id"] == w["id"] })
			switch {
			case i < 0:
				have = append(have, w)
				added++
			case !sameValue(have[i], w):
				id, _ := w["id"].(string)
				if slices.Contains(d.ReposItems, id) && !o.update {
					// Over more repositories than before: the template's own
					// rule, checked by appliedRepos.
					have[i] = w
					added++
					continue
				}
				wantJSON, _ := json.Marshal(w, json.Deterministic(true))
				curJSON, _ := json.Marshal(have[i], json.Deterministic(true))
				s.notes = append(s.notes, fmt.Sprintf("%s %s now: %s", what, id, curJSON), "the template's: "+string(wantJSON))
				have[i] = w
				changed++
			}
		}
		return have
	}
	rules = merge(rules, d.Rules, "rule")
	tests = merge(tests, d.Tests, "test")
	if d.PerRepo {
		s.notes = append(s.notes, "one rule of each kind per repository: applying for other repositories never changes these, and pclaw template remove takes them away")
	}
	if len(d.Skipped) > 0 {
		s.notes = append(s.notes, "skipped for want of an agent (pass --agent ID): "+strings.Join(d.Skipped, ", "))
	} else if o.agent != "" {
		s.notes = append(s.notes, "the agent's rules hold for agent "+o.agent+"'s runs only")
	}
	if len(d.Tests) > 0 {
		s.notes = append(s.notes, fmt.Sprintf("with %d scenario tests, which the publish gate runs with every test of the policy", len(d.Tests)))
	}
	switch {
	case changed > 0:
		s.state = stepDiffers
	case added > 0:
		s.state = stepCreate
	default:
		s.state = stepUnchanged
		return s, nil
	}
	bundle["rules"] = rules
	if len(tests) > 0 {
		bundle["tests"] = tests
	}
	s.notes = append(s.notes, "published as a new version of the org's policy once it passes validation and its tests; a loosening waits for confirmations")
	s.bundle, s.planned = bundle, planned
	s.apply = publishBundle(c, bundle, planned, func(ctx context.Context) (string, error) {
		return replanPolicy(ctx, c, o, d, 1)
	})
	return s, nil
}

// publishedBundle reads the published policy bundle and its version id
// ("" and an empty bundle when none is published).
func publishedBundle(ctx context.Context, c clients) (map[string]any, string, error) {
	bundle := map[string]any{"id": "org-policy", "rules": []any{}}
	res, err := c.policies.GetPublishedPolicy(ctx, &pantherclawv1.GetPublishedPolicyRequest{})
	switch {
	case connect.CodeOf(err) == connect.CodeNotFound:
		return bundle, "", nil
	case err != nil:
		return nil, "", err
	case res.GetVersion() == nil:
		// The server answers an empty response when nothing is published.
		return bundle, "", nil
	}
	if err := json.Unmarshal(res.GetVersion().GetBundle(), &bundle); err != nil {
		return nil, "", fmt.Errorf("the published policy: %w", err)
	}
	delete(bundle, "version")
	return bundle, res.GetVersion().GetId(), nil
}

// publishBundle creates the bundle as a new version and publishes it. The
// bundle is the version published at planning time, edited: the server
// refuses both calls (POLICY_PUBLISHED_CHANGED) once another version is
// published, so that version's changes are never dropped. Then retry, when
// set, plans again from the new version; without it nothing is published.
func publishBundle(c clients, bundle map[string]any, planned string, retry func(context.Context) (string, error)) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		raw, err := json.Marshal(bundle, json.Deterministic(true))
		if err != nil {
			return "", err
		}
		v, err := c.policies.CreatePolicyVersion(ctx, &pantherclawv1.CreatePolicyVersionRequest{Bundle: raw, ExpectedCurrentVersion: &planned})
		var pub *pantherclawv1.PublishPolicyVersionResponse
		if err == nil {
			pub, err = c.policies.PublishPolicyVersion(ctx, &pantherclawv1.PublishPolicyVersionRequest{Id: v.GetVersion().GetId(), ExpectedCurrentVersion: &planned})
		}
		switch {
		case publishedChanged(err) && retry != nil:
			return retry(ctx)
		case publishedChanged(err):
			return "", errPublishedChanged
		case err != nil:
			return "", err
		}
		if cr := pub.GetChangeRequest(); cr != nil {
			return "", &waitingError{msg: fmt.Sprintf(
				"policy version %d loosens the published policy, so %d %s holding policy.publish must confirm it with a security key within 24 hours at %s",
				v.GetVersion().GetVersion(), cr.GetRequired(), people(cr.GetRequired()), cr.GetUrl())}
		}
		return fmt.Sprintf("policy version %d published", v.GetVersion().GetVersion()), nil
	}
}

// waitingError: the policy version went through the gate and waits for
// confirmations (a PUBLISH change request, D6); nothing failed.
type waitingError struct{ msg string }

func (e *waitingError) Error() string { return "waiting for confirmation: " + e.msg }

// errPublishedChanged: another policy version was published after the plan.
var errPublishedChanged = errors.New("another policy version was published since the plan; nothing was published. Run the command again to see the new plan")

// publishedChanged reports the server's POLICY_PUBLISHED_CHANGED refusal.
func publishedChanged(err error) bool {
	return connect.CodeOf(err) == connect.CodeFailedPrecondition && strings.Contains(err.Error(), "POLICY_PUBLISHED_CHANGED")
}

func ruleIDs(rules []map[string]any) string {
	ids := make([]string, len(rules))
	for i, r := range rules {
		ids[i], _ = r["id"].(string)
	}
	return strings.Join(ids, ", ")
}

// planWindow sets the example change window for the environment.
func planWindow(ctx context.Context, c clients, _ templateOptions, d templateData, _ string) (templateStep, error) {
	want := d.Window
	if want == nil {
		return templateStep{what: "change window", state: stepSkipped, notes: []string{"the template sets no change window"}}, nil
	}
	s := templateStep{what: fmt.Sprintf("change window for %s: Mon–Fri 09:00–17:00 %s", want.GetEnvironment(), want.GetTimeZone())}
	res, err := c.windows.ListChangeWindows(ctx, &pantherclawv1.ListChangeWindowsRequest{Environment: want.GetEnvironment()})
	if err != nil {
		return s, err
	}
	var cur *pantherclawv1.ChangeWindow
	for _, w := range res.GetWindows() {
		if w.GetState() == "ACTIVE" && w.GetRepository() == "" && strings.EqualFold(w.GetEnvironment(), want.GetEnvironment()) {
			cur = w
		}
	}
	same := func(w *pantherclawv1.ChangeWindow) bool {
		if w.GetTimeZone() != want.GetTimeZone() || len(w.GetOneOff()) > 0 || len(w.GetFreezes()) > 0 || len(w.GetWeekly()) != len(want.GetWeekly()) {
			return false
		}
		for i, e := range w.GetWeekly() {
			x := want.GetWeekly()[i]
			if e.GetDay() != x.GetDay() || e.GetStart() != x.GetStart() || e.GetMinutes() != x.GetMinutes() {
				return false
			}
		}
		return true
	}
	switch {
	case cur == nil:
		s.state = stepCreate
	case same(cur):
		s.state = stepUnchanged
		return s, nil
	default:
		s.state = stepDiffers
		s.notes = append(s.notes, fmt.Sprintf("the active window %s differs (time zone %s, %d weekly entries, %d one-off, %d freezes); the template's replaces it",
			cur.GetId(), cur.GetTimeZone(), len(cur.GetWeekly()), len(cur.GetOneOff()), len(cur.GetFreezes())))
	}
	s.apply = func(ctx context.Context) (string, error) {
		res, err := c.windows.CreateChangeWindow(ctx, want)
		return "change window " + res.GetWindow().GetId() + " created", err
	}
	return s, nil
}

// planGrant issues the agent's grant: the person applying is its principal.
func planGrant(ctx context.Context, c clients, o templateOptions, d templateData, me string) (templateStep, error) {
	if o.agent == "" {
		return templateStep{what: "grant", state: stepSkipped, notes: []string{"grant skipped: no agent (pass --agent ID)"}}, nil
	}
	ceiling, err := grantCeiling(ctx, c, o)
	if err != nil {
		return templateStep{what: "grant"}, err
	}
	expires := o.expires
	if expires > ceiling {
		// A minute short of the ceiling, so the server's clock never finds it over.
		expires = ceiling - time.Minute
	}
	s := templateStep{
		what:  fmt.Sprintf("grant to agent %s for %s, for %s", o.agent, d.TaskRef, expires),
		notes: []string{d.Info.Grant},
	}
	if expires < o.expires {
		s.notes = append(s.notes, fmt.Sprintf("capped by the org's grant ceiling of %s (asked for %s)", ceiling, o.expires))
	}
	agent := o.agent
	var cur *pantherclawv1.Grant
	for token := ""; ; {
		res, err := c.grants.ListGrants(ctx, &pantherclawv1.ListGrantsRequest{
			PageSize: 200, PageToken: token, AgentId: &agent, State: pantherclawv1.GrantState_GRANT_STATE_ACTIVE,
		})
		if err != nil {
			return s, err
		}
		for _, g := range res.GetGrants() {
			if g.GetTaskRef() == d.TaskRef && g.GetParentGrantId() == "" {
				cur = g
			}
		}
		if token = res.GetNextPageToken(); token == "" || cur != nil {
			break
		}
	}
	switch {
	case cur == nil:
		s.state = stepCreate
		s.apply = func(ctx context.Context) (string, error) {
			res, err := c.grants.IssueGrant(ctx, &pantherclawv1.IssueGrantRequest{
				AgentId: o.agent, Principal: &pantherclawv1.Actor{Kind: "user", Id: me}, TaskRef: d.TaskRef,
				ExpireTime: timestamppb.New(time.Now().Add(expires)), Bounds: d.Grant.Bounds, Limits: d.Grant.Limits,
			})
			return "grant " + res.GetGrant().GetId() + " issued", err
		}
	case sameJSON(cur.GetBounds(), d.Grant.Bounds) && sameJSON(cur.GetLimits(), d.Grant.Limits):
		s.state = stepUnchanged
	default:
		s.state = stepDiffers
		s.notes = append(s.notes, fmt.Sprintf("grant %s differs: bounds %s, limits %s", cur.GetId(), cur.GetBounds(), cur.GetLimits()))
		s.apply = func(ctx context.Context) (string, error) {
			res, err := c.grants.ReviseGrant(ctx, &pantherclawv1.ReviseGrantRequest{
				Id: cur.GetId(), Revision: cur.GetRevision(), TaskRef: cur.GetTaskRef(), ExpireTime: cur.GetExpireTime(),
				Bounds: d.Grant.Bounds, Requirements: cur.GetRequirements(), Limits: d.Grant.Limits, Delegation: cur.GetDelegation(),
			})
			return fmt.Sprintf("grant %s revised to %d", cur.GetId(), res.GetGrant().GetRevision()), err
		}
	}
	return s, nil
}

// grantCeiling is the longest a person's grant may last: the org
// guardrail's max_root_lifetime (7 days unless set, at most 90), lowered by
// the --team or --bu guardrail's. A guardrail of the agent's own team or
// environment may lower it further; the server then refuses the grant.
func grantCeiling(ctx context.Context, c clients, o templateOptions) (time.Duration, error) {
	const def, hard = 7 * 24 * time.Hour, 90 * 24 * time.Hour
	settings := func(kind pantherclawv1.GuardrailScopeKind, id string) (*pantherclawv1.GuardrailSettings, error) {
		for token := ""; ; {
			res, err := c.guardrails.ListEnvelopes(ctx, &pantherclawv1.ListEnvelopesRequest{PageSize: 200, PageToken: token, Kind: kind})
			if err != nil {
				return nil, err
			}
			for _, e := range res.GetEnvelopes() {
				if kind == pantherclawv1.GuardrailScopeKind_GUARDRAIL_SCOPE_KIND_ORG || e.GetScope().GetId() == id {
					return e.GetSettings(), nil
				}
			}
			if token = res.GetNextPageToken(); token == "" {
				return nil, nil
			}
		}
	}
	ceiling := def
	org, err := settings(pantherclawv1.GuardrailScopeKind_GUARDRAIL_SCOPE_KIND_ORG, "")
	if err != nil {
		return 0, err
	}
	if org.GetMaxRootLifetime() != nil {
		ceiling = min(org.GetMaxRootLifetime().AsDuration(), hard)
	}
	kind, id := pantherclawv1.GuardrailScopeKind_GUARDRAIL_SCOPE_KIND_TEAM, o.team
	if o.bu != "" {
		kind, id = pantherclawv1.GuardrailScopeKind_GUARDRAIL_SCOPE_KIND_BUSINESS_UNIT, o.bu
	}
	if id != "" {
		scoped, err := settings(kind, id)
		if err != nil {
			return 0, err
		}
		if scoped.GetMaxRootLifetime() != nil {
			ceiling = min(ceiling, scoped.GetMaxRootLifetime().AsDuration())
		}
	}
	return ceiling, nil
}

// monitorWarnings names each connection route the template's rules are
// for (template.json routes) that runs in monitor mode: there a rule's
// decision is recorded and never blocks (coverage OBSERVE_ONLY).
func monitorWarnings(ctx context.Context, c clients, info templateInfo) []string {
	if len(info.Routes) == 0 {
		return nil
	}
	var out []string
	for token := ""; ; {
		res, err := c.connections.ListConnections(ctx, &pantherclawv1.ListConnectionsRequest{PageSize: 200, PageToken: token})
		if err != nil {
			return []string{"could not read the connections' route modes (" + describe(err) + "); in monitor mode the rules record decisions and do not block"}
		}
		for _, conn := range res.GetConnections() {
			if !slices.ContainsFunc(info.Routes, func(r templateRoute) bool { return r.Package == conn.GetPackage() }) {
				continue
			}
			got, err := c.connections.GetConnection(ctx, &pantherclawv1.GetConnectionRequest{Id: conn.GetId()})
			if err != nil {
				out = append(out, fmt.Sprintf("could not read connection %s's route modes (%s)", conn.GetName(), describe(err)))
				continue
			}
			for _, tr := range info.Routes {
				if tr.Package != conn.GetPackage() {
					continue
				}
				route := tr.Route
				mode := got.GetConnection().GetDefaultMode()
				for _, r := range got.GetConnection().GetRoutes() {
					if r.GetRoute() == route {
						mode = r.GetMode()
					}
				}
				if mode != pantherclawv1.RouteMode_ROUTE_MODE_ENFORCE {
					out = append(out, fmt.Sprintf("connection %s's route %s is in monitor mode: the rules are recorded but do not block (coverage OBSERVE_ONLY)", conn.GetName(), route))
				}
			}
		}
		if token = res.GetNextPageToken(); token == "" {
			return out
		}
	}
}

// policyRetries bounds how often the policy step plans again because
// another version was published meanwhile.
const policyRetries = 3

// replanPolicy plans the policy step again from the version published now
// and applies it, when that changes nothing the person did not confirm: the
// template's rules are added as confirmed, and a rule of the template's
// that the new version changed is replaced only with --update.
func replanPolicy(ctx context.Context, c clients, o templateOptions, d templateData, attempt int) (string, error) {
	if attempt > policyRetries {
		return "", errPublishedChanged
	}
	s, err := planPolicy(ctx, c, o, d, "")
	if err != nil {
		return "", err
	}
	switch {
	case s.state == stepUnchanged:
		return "the published policy has the template's rules already", nil
	case s.state == stepDiffers && !o.update:
		return "", errors.New("another policy version was published since the plan, and it changes the template's rules; nothing was published. Run the command again to see the new plan")
	}
	// The new plan's apply retries with the next attempt.
	return publishBundle(c, s.bundle, s.planned, func(ctx context.Context) (string, error) {
		return replanPolicy(ctx, c, o, d, attempt+1)
	})(ctx)
}
