// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/templates"
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
		usage: "template apply NAME --repos OWNER/REPO[,OWNER/REPO…] [--agent ID] [--team ID | --bu ID] [--environment NAME] " +
			"[--time-zone TZ] [--default-branch BRANCH | --default-branch OWNER/REPO=BRANCH]… [--expires DURATION] [--dry-run] [--update] [--yes]",
		run: templateApply,
	}
}

// templateOptions are what a template is applied with.
type templateOptions struct {
	name                  string
	repos                 []string
	defaults              map[string]string // repository → default branch
	agent, team, bu       string
	environment, timeZone string
	expires               time.Duration
	dryRun, update, yes   bool
	// planOnly, set by init --yes without --yes-template, shows the plan
	// and applies nothing.
	planOnly bool
}

var (
	templateNameRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	// templateRepoRe is a GitHub repository as pc.github names targets.
	templateRepoRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,38}/\.?[a-z0-9_-][a-z0-9._-]{0,98}$`)
	templateBranchRe = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9._-]{0,99}(/[A-Za-z0-9_-][A-Za-z0-9._-]{0,99}){0,7}$`)
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
	fs.StringVar(&o.team, "team", "", "bound the grants of this team's agents to the repositories (a guardrail envelope)")
	fs.StringVar(&o.bu, "bu", "", "bound the grants of this business unit's agents to the repositories (a guardrail envelope)")
	fs.StringVar(&o.environment, "environment", "production", "the deployment environment of the example change window")
	fs.StringVar(&o.timeZone, "time-zone", "UTC", "the change window's time zone")
	fs.DurationVar(&o.expires, "expires", 30*24*time.Hour, "how long the agent's grant lasts")
	return func() error {
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
		if len(o.repos) == 0 {
			return errors.New("--repos names no repository")
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

// templateData is a template rendered for its options.
type templateData struct {
	TaskRef  string
	Envelope struct {
		Name   string
		Bounds []byte
	}
	Grant struct {
		Bounds, Limits []byte
	}
	Rules []map[string]any
	// Skipped are the agent rules left out for want of an agent.
	Skipped []string
	Window  *pantherclawv1.CreateChangeWindowRequest
}

// ruleIDMax is the longest policy rule id.
const ruleIDMax = 64

// repoRuleID is a per-repository rule's id: c2p-<kind>--<owner>-<repo>-<6
// hex>, the owner and repository lowercased with anything outside [a-z0-9]
// turned into "-", and the hex from sha256 of the exact "owner/repo", so
// repositories that differ only in case or punctuation never share an id.
// A long name is cut, the hash kept.
func repoRuleID(base, repo string) string {
	slug := []byte(strings.ToLower(repo))
	for i, b := range slug {
		if (b < 'a' || b > 'z') && (b < '0' || b > '9') {
			slug[i] = '-'
		}
	}
	sum := sha256.Sum256([]byte(repo))
	hash := "-" + hex.EncodeToString(sum[:])[:6]
	prefix := base + "--" + string(slug)
	if len(prefix)+len(hash) > ruleIDMax {
		prefix = prefix[:ruleIDMax-len(hash)]
	}
	return prefix + hash
}

// fillRule copies a template rule with its id and its condition filled in.
func fillRule(r map[string]any, id string, when *strings.Replacer) (map[string]any, error) {
	raw, err := json.Marshal(r, json.Deterministic(true))
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	out["id"] = id
	if w, ok := out["when"].(string); ok {
		out["when"] = when.Replace(w)
	}
	return out, nil
}

// renderTemplate reads the template's files and fills in the options:
// "{{repo}}" in a list item repeats the item for each repository, and the
// other placeholders are replaced by CEL lists over the repositories'
// targets, the environment and the time zone.
func renderTemplate(o templateOptions) (templateData, error) {
	var out templateData
	if !templateNameRe.MatchString(o.name) {
		return out, fmt.Errorf("no template %q", o.name)
	}
	scalar := strings.NewReplacer("{{environment}}", o.environment, "{{time_zone}}", o.timeZone)
	var walk func(v any) any
	walk = func(v any) any {
		switch v := v.(type) {
		case map[string]any:
			for k, x := range v {
				v[k] = walk(x)
			}
			return v
		case []any:
			var list []any
			for _, x := range v {
				if s, ok := x.(string); ok && strings.Contains(s, "{{repo}}") {
					for _, r := range o.repos {
						list = append(list, strings.ReplaceAll(s, "{{repo}}", r))
					}
					continue
				}
				list = append(list, walk(x))
			}
			return list
		case string:
			return scalar.Replace(v)
		}
		return v
	}
	read := func(file string, into any) error {
		raw, err := fs.ReadFile(templates.FS, o.name+"/"+file)
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("no template %q", o.name)
		} else if err != nil {
			return err
		}
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			return fmt.Errorf("template %s/%s: %w", o.name, file, err)
		}
		b, err := json.Marshal(walk(v), json.Deterministic(true))
		if err != nil {
			return err
		}
		return json.Unmarshal(b, into)
	}
	var meta struct {
		TaskRef string `json:"task_ref"`
	}
	var env struct {
		Name   string `json:"name"`
		Bounds any    `json:"bounds"`
	}
	var grant struct {
		Bounds any `json:"bounds"`
		Limits any `json:"limits"`
	}
	var policy struct {
		Rules []map[string]any `json:"rules"`
	}
	var window struct {
		Environment string `json:"environment"`
		TimeZone    string `json:"time_zone"`
		Weekly      []struct {
			Day     string `json:"day"`
			Start   string `json:"start"`
			Minutes int32  `json:"minutes"`
		} `json:"weekly"`
	}
	for file, into := range map[string]any{
		"template.json": &meta, "envelope.json": &env, "grant.json": &grant, "policy.json": &policy, "window.json": &window,
	} {
		if err := read(file, into); err != nil {
			return out, err
		}
	}
	var err error
	out.TaskRef, out.Envelope.Name = meta.TaskRef, env.Name
	for _, r := range policy.Rules {
		per, _ := r["per"].(string)
		delete(r, "per")
		base, _ := r["id"].(string)
		switch per {
		case "repo":
			// A rule per repository, so applying for one repository never
			// changes another's rules (the coordinator's decision Q8).
			for _, repo := range o.repos {
				rule, err := fillRule(r, repoRuleID(base, repo), strings.NewReplacer(
					"{{pull_request}}", "action.target.id.startsWith('"+repo+"#')",
					"{{repository}}", "action.target.id == '"+repo+"'",
					"{{default_ref}}", "action.target.id == '"+repo+"@refs/heads/"+o.defaults[repo]+"'",
				))
				if err != nil {
					return out, err
				}
				out.Rules = append(out.Rules, rule)
			}
		case "agent":
			// A rule for the template's agent only, through the run the
			// server records for each action (`run.agent_id`).
			if o.agent == "" {
				out.Skipped = append(out.Skipped, base)
				continue
			}
			rule, err := fillRule(r, base+"--"+o.agent, strings.NewReplacer("{{agent}}", o.agent))
			if err != nil {
				return out, err
			}
			out.Rules = append(out.Rules, rule)
		default:
			return out, fmt.Errorf("template %s: rule %s: per must be repo or agent", o.name, base)
		}
	}
	if out.Envelope.Bounds, err = json.Marshal(env.Bounds, json.Deterministic(true)); err != nil {
		return out, err
	}
	if out.Grant.Bounds, err = json.Marshal(grant.Bounds, json.Deterministic(true)); err != nil {
		return out, err
	}
	if out.Grant.Limits, err = json.Marshal(grant.Limits, json.Deterministic(true)); err != nil {
		return out, err
	}
	out.Window = &pantherclawv1.CreateChangeWindowRequest{Environment: window.Environment, TimeZone: window.TimeZone}
	for _, w := range window.Weekly {
		out.Window.Weekly = append(out.Window.Weekly, &pantherclawv1.WeeklyEntry{Day: w.Day, Start: w.Start, Minutes: w.Minutes})
	}
	return out, nil
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
}

const (
	stepCreate    = "create"
	stepUnchanged = "unchanged"
	stepDiffers   = "differs"
	stepUpdate    = "update"
	stepSkipped   = "skipped"
)

func applyTemplate(ctx context.Context, a *app, o templateOptions) error {
	data, err := renderTemplate(o)
	if err != nil {
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
	_, _ = fmt.Fprintf(w, "Template %s for %s, as %s:\n", o.name, strings.Join(o.repos, ", "), me.GetPrincipal().GetDisplayName())
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
	for _, r := range o.repos {
		_, _ = fmt.Fprintf(w, "  Protects %s's default branch %s from writes; renaming a default branch needs this template applied again.\n", r, o.defaults[r])
	}
	_, _ = fmt.Fprintln(w, "  Binds no people to roles: bind code_reviewer and release_approver yourself (pclaw role bind).")
	for _, warn := range monitorWarnings(ctx, c) {
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
	if id == "" {
		return templateStep{what: "guardrail envelope", state: stepSkipped, notes: []string{
			"warning: no envelope; pass --team (or --bu) to bound that team's grants to these repositories. The grant's own bounds hold either way.",
		}}, nil
	}
	s := templateStep{
		what:  fmt.Sprintf("guardrail envelope %q on %s %s", d.Envelope.Name, strings.ToLower(strings.TrimPrefix(kind.String(), "GUARDRAIL_SCOPE_KIND_")), id),
		notes: []string{"every grant of its agents is limited to the GitHub operations on these repositories"},
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
	switch {
	case cur == nil:
		s.state = stepCreate
		s.apply = func(ctx context.Context) (string, error) {
			res, err := c.guardrails.CreateEnvelope(ctx, &pantherclawv1.CreateEnvelopeRequest{
				Scope: &pantherclawv1.GuardrailScope{Kind: kind, Id: id}, Name: d.Envelope.Name, Bounds: d.Envelope.Bounds,
			})
			return "guardrail envelope " + res.GetEnvelope().GetId() + " created", err
		}
	case sameJSON(cur.GetBounds(), d.Envelope.Bounds):
		s.state = stepUnchanged
	default:
		s.state = stepDiffers
		s.notes = append(s.notes, "its bounds now: "+string(cur.GetBounds()), "the template's: "+string(d.Envelope.Bounds))
		s.apply = func(ctx context.Context) (string, error) {
			res, err := c.guardrails.ReviseEnvelope(ctx, &pantherclawv1.ReviseEnvelopeRequest{
				Id: cur.GetId(), Revision: cur.GetRevision(), Name: cur.GetName(), Bounds: d.Envelope.Bounds,
				Requirements: cur.GetRequirements(), Limits: cur.GetLimits(), Settings: cur.GetSettings(), MinAttestationLevel: cur.GetMinAttestationLevel(),
			})
			return fmt.Sprintf("guardrail envelope %s revised to %d", cur.GetId(), res.GetEnvelope().GetRevision()), err
		}
	}
	return s, nil
}

// planPolicy adds the template's rules to the published bundle, as a new
// version that is then published.
func planPolicy(ctx context.Context, c clients, o templateOptions, d templateData, _ string) (templateStep, error) {
	s := templateStep{what: "policy rules " + ruleIDs(d.Rules)}
	bundle, planned, err := publishedBundle(ctx, c)
	if err != nil {
		return s, err
	}
	rules, _ := bundle["rules"].([]any)
	added, changed := 0, 0
	for _, want := range d.Rules {
		i := slices.IndexFunc(rules, func(r any) bool { m, _ := r.(map[string]any); return m["id"] == want["id"] })
		switch {
		case i < 0:
			rules = append(rules, want)
			added++
		case !reflect.DeepEqual(rules[i], any(want)):
			wantJSON, _ := json.Marshal(want, json.Deterministic(true))
			curJSON, _ := json.Marshal(rules[i], json.Deterministic(true))
			s.notes = append(s.notes, fmt.Sprintf("rule %v now: %s", want["id"], curJSON), "the template's: "+string(wantJSON))
			rules[i] = want
			changed++
		}
	}
	s.notes = append(s.notes, "one rule of each kind per repository: applying for other repositories never changes these, and pclaw template remove takes them away")
	if len(d.Skipped) > 0 {
		s.notes = append(s.notes, "shell rule skipped: no agent (pass --agent ID)")
	} else {
		s.notes = append(s.notes, "the shell rule holds for agent "+o.agent+"'s runs only")
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
	s.notes = append(s.notes, "published as a new version of the org's policy")
	s.apply = publishBundle(c, bundle, planned)
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
	}
	if err := json.Unmarshal(res.GetVersion().GetBundle(), &bundle); err != nil {
		return nil, "", fmt.Errorf("the published policy: %w", err)
	}
	delete(bundle, "version")
	return bundle, res.GetVersion().GetId(), nil
}

// publishBundle creates the bundle as a new version and publishes it. The
// bundle is the version published at planning time, edited: if another
// version was published since, publishing it would silently drop that
// version's changes, so nothing is published then.
func publishBundle(c clients, bundle map[string]any, planned string) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		if err := samePublished(ctx, c, planned); err != nil {
			return "", err
		}
		raw, err := json.Marshal(bundle, json.Deterministic(true))
		if err != nil {
			return "", err
		}
		v, err := c.policies.CreatePolicyVersion(ctx, &pantherclawv1.CreatePolicyVersionRequest{Bundle: raw})
		if err != nil {
			return "", err
		}
		if err := samePublished(ctx, c, planned); err != nil {
			return "", err
		}
		if _, err := c.policies.PublishPolicyVersion(ctx, &pantherclawv1.PublishPolicyVersionRequest{Id: v.GetVersion().GetId()}); err != nil {
			return "", err
		}
		return fmt.Sprintf("policy version %d published", v.GetVersion().GetVersion()), nil
	}
}

// samePublished fails unless the published policy version is still the one
// the plan was made from ("" for none).
func samePublished(ctx context.Context, c clients, planned string) error {
	res, err := c.policies.GetPublishedPolicy(ctx, &pantherclawv1.GetPublishedPolicyRequest{})
	if err != nil && connect.CodeOf(err) != connect.CodeNotFound {
		return err
	}
	if now := res.GetVersion().GetId(); now != planned {
		return errors.New("another policy version was published since the plan; nothing was published. Apply the template again to see the new plan")
	}
	return nil
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
		notes: []string{"reads, branch preparation, contents writes, pull requests and merges on these repositories; one merge per run"},
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

// templateRoutes are the pc.github routes whose decisions the template's
// rules are for.
var templateRoutes = []string{"github-pull-merge", "github-contents-write", "github-branch-create"}

// monitorWarnings names each pc.github connection route the template's
// rules are for that runs in monitor mode: there a rule's decision is
// recorded and never blocks (coverage OBSERVE_ONLY).
func monitorWarnings(ctx context.Context, c clients) []string {
	var out []string
	for token := ""; ; {
		res, err := c.connections.ListConnections(ctx, &pantherclawv1.ListConnectionsRequest{PageSize: 200, PageToken: token})
		if err != nil {
			return []string{"could not read the connections' route modes (" + describe(err) + "); in monitor mode the rules record decisions and do not block"}
		}
		for _, conn := range res.GetConnections() {
			if conn.GetPackage() != "pc.github" {
				continue
			}
			got, err := c.connections.GetConnection(ctx, &pantherclawv1.GetConnectionRequest{Id: conn.GetId()})
			if err != nil {
				out = append(out, fmt.Sprintf("could not read connection %s's route modes (%s)", conn.GetName(), describe(err)))
				continue
			}
			for _, route := range templateRoutes {
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
