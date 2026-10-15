// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"github.com/katocxl/pantherclaw/internal/actionir"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/templates"
)

// Rendering a template (G0 M8 C4; M11.1 D16 and D27): its template.json
// declares every placeholder its files use, each with a kind and a pattern.
// A value is checked against both before it is used, and a value that goes
// into a rule's condition is inserted only as a quoted CEL string literal
// (celQuote), never pasted into the expression text. A placeholder the
// template does not declare is an error, so a template cannot use a value
// nobody checked.
//
// Rules and tests in policy.json and tests.json carry "per": "org" (once),
// "repo" (once per repository, its id made per repository) or "agent"
// (once for --agent, skipped without one).

// placeholderSpec is one declared placeholder.
type placeholderSpec struct {
	Kind    string `json:"kind"`
	Pattern string `json:"pattern"`
}

// Placeholder kinds; a template's placeholder is named after its kind.
const (
	kindRepository    = "repository"
	kindDefaultBranch = "default_branch"
	kindEnvironment   = "environment"
	kindEnvironmentID = "environment_id"
	kindWorkspace     = "workspace"
	kindAgent         = "agent"
	kindTimeZone      = "time_zone"
)

// placeholderKinds are the kinds and the checks a value of each must pass
// besides its declared pattern.
var placeholderKinds = map[string]func(string) error{
	kindRepository: func(v string) error {
		if !templateRepoRe.MatchString(v) {
			return errors.New("not a lowercase owner/repo")
		}
		return nil
	},
	kindDefaultBranch: func(v string) error {
		if !templateBranchRe.MatchString(v) {
			return errors.New("not a branch name")
		}
		return nil
	},
	kindEnvironment: func(string) error { return nil },
	kindEnvironmentID: func(v string) error {
		if !uuidRe.MatchString(v) {
			return errors.New("not an id")
		}
		return nil
	},
	kindWorkspace: func(v string) error {
		if n, err := actionir.NormalizePath(v); err != nil || n != v || !strings.HasPrefix(v, "/") {
			return errors.New("not a normalized absolute path")
		}
		return nil
	},
	kindAgent: func(v string) error {
		if !uuidRe.MatchString(v) {
			return errors.New("not an id")
		}
		return nil
	},
	kindTimeZone: func(string) error { return nil },
}

// placeholderFlags name the option each kind's value comes from.
var placeholderFlags = map[string]string{
	kindRepository: "--repos", kindDefaultBranch: "--default-branch", kindEnvironment: "--environment",
	kindEnvironmentID: "--environment", kindWorkspace: "--workspace", kindAgent: "--agent", kindTimeZone: "--time-zone",
}

// otherEnvironmentID is {{other_environment_id}}: an environment id that
// is never the template's, for tests that show a rule stays in its
// environment.
const otherEnvironmentID = "00000000-0000-7000-8000-0000000000e9"

// celQuote is s as a CEL string literal. Values are checked against their
// patterns first; quoting is the second line, so a value can never end the
// literal and change the condition.
func celQuote(s string) string {
	var b strings.Builder
	b.WriteByte('\'')
	for _, r := range s {
		switch {
		case r == '\\' || r == '\'':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, "\\x%02x", r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('\'')
	return b.String()
}

// templateData is a template rendered for its options.
type templateData struct {
	Info     templateInfo
	TaskRef  string
	Envelope struct {
		Present bool
		Name    string
		Bounds  []byte
	}
	Grant struct {
		Bounds, Limits []byte
	}
	Rules []map[string]any
	Tests []map[string]any
	// Skipped are the agent rules and tests left out for want of an agent.
	Skipped []string
	// Window is nil when the template sets none.
	Window *pantherclawv1.CreateChangeWindowRequest
	// PerRepo: some of its rules are per repository.
	PerRepo bool
	// ReposItems are the ids of the org rules and tests rendered over every
	// repository ({{repos}}).
	ReposItems []string
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

var placeholderRe = regexp.MustCompile(`\{\{([a-z_]+)\}\}`)

// renderer fills one template's placeholders for its options.
type renderer struct {
	o    templateOptions
	spec map[string]placeholderSpec
}

// declared reports whether the template declares a kind.
func (r renderer) declared(kind string) bool { _, ok := r.spec[kind]; return ok }

// value is a placeholder's text: a CEL expression or a quoted literal in a
// condition (cel), the bare value elsewhere. repo is the repository of a
// per-repository item.
func (r renderer) value(name, repo string, cel bool) (string, error) {
	needRepo := func() error {
		if repo == "" {
			return fmt.Errorf("{{%s}} is used outside a per-repository item", name)
		}
		return nil
	}
	quote := func(s string) string {
		if cel {
			return celQuote(s)
		}
		return s
	}
	macro := func() error {
		if !cel {
			return fmt.Errorf("{{%s}} is a condition and is used outside one", name)
		}
		if !r.declared(kindRepository) {
			return fmt.Errorf("{{%s}} needs the repository placeholder declared", name)
		}
		return nil
	}
	switch name {
	case "repo":
		if !r.declared(kindRepository) {
			break
		}
		if err := needRepo(); err != nil {
			return "", err
		}
		return quote(repo), nil
	case "repository":
		if err := errors.Join(macro(), needRepo()); err != nil {
			return "", err
		}
		return "action.target.id == " + celQuote(repo), nil
	case "pull_request":
		if err := errors.Join(macro(), needRepo()); err != nil {
			return "", err
		}
		return "action.target.id.startsWith(" + celQuote(repo+"#") + ")", nil
	case "default_ref":
		if err := errors.Join(macro(), needRepo()); err != nil {
			return "", err
		}
		if !r.declared(kindDefaultBranch) {
			return "", errors.New("{{default_ref}} needs the default_branch placeholder declared")
		}
		return "action.target.id == " + celQuote(repo+"@refs/heads/"+r.o.defaults[repo]), nil
	case "repos":
		if err := macro(); err != nil {
			return "", err
		}
		q := make([]string, len(r.o.repos))
		for i, x := range r.o.repos {
			q[i] = celQuote(x)
		}
		return "[" + strings.Join(q, ", ") + "]", nil
	case "other_environment_id":
		if r.declared(kindEnvironmentID) {
			return quote(otherEnvironmentID), nil
		}
	case "no_environment_decision", "no_environment_reason":
		// What a direct deployment that names no environment, which goes
		// to production, expects (M11.1 D21): held when the template is
		// for production, refused otherwise.
		if r.declared(kindEnvironment) && !cel {
			prod := r.o.environment == "production"
			switch {
			case name == "no_environment_decision" && prod:
				return "REQUIRE_APPROVAL", nil
			case name == "no_environment_decision":
				return "DENY", nil
			case prod:
				return "DEPLOYMENT_NEEDS_RELEASE", nil
			}
			return "DEPLOYMENT_ENVIRONMENT_NOT_ALLOWED", nil
		}
	}
	if !r.declared(name) || name == kindRepository {
		return "", fmt.Errorf("{{%s}} is not a declared placeholder", name)
	}
	var v string
	switch name {
	case kindDefaultBranch:
		if err := needRepo(); err != nil {
			return "", err
		}
		v = r.o.defaults[repo]
	case kindEnvironment:
		v = r.o.environment
	case kindEnvironmentID:
		v = r.o.environmentID
	case kindWorkspace:
		v = r.o.workspace
	case kindAgent:
		v = r.o.agent
	case kindTimeZone:
		v = r.o.timeZone
	}
	switch {
	case v == "" && name == kindEnvironmentID:
		return "", errNeedsEnvironmentID
	case v == "":
		return "", fmt.Errorf("{{%s}} needs %s", name, placeholderFlags[name])
	}
	return quote(v), nil
}

// fill replaces the placeholders in s.
func (r renderer) fill(s, repo string, cel bool) (string, error) {
	var errs []error
	out := placeholderRe.ReplaceAllStringFunc(s, func(m string) string {
		v, err := r.value(m[2:len(m)-2], repo, cel)
		errs = append(errs, err)
		return v
	})
	return out, errors.Join(errs...)
}

// walk fills every string of a JSON value: "when" members as conditions,
// everything else as text. Outside items (repo == ""), a list item that
// names {{repo}} is repeated for each repository.
func (r renderer) walk(v any, repo string, when bool) (any, error) {
	switch v := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, x := range v {
			y, err := r.walk(x, repo, k == "when")
			if err != nil {
				return nil, err
			}
			out[k] = y
		}
		return out, nil
	case []any:
		out := make([]any, 0, len(v))
		for _, x := range v {
			if s, ok := x.(string); ok && repo == "" && strings.Contains(s, "{{repo}}") {
				for _, each := range r.o.repos {
					y, err := r.fill(s, each, false)
					if err != nil {
						return nil, err
					}
					out = append(out, y)
				}
				continue
			}
			y, err := r.walk(x, repo, false)
			if err != nil {
				return nil, err
			}
			out = append(out, y)
		}
		return out, nil
	case string:
		return r.fill(v, repo, when)
	}
	return v, nil
}

// items renders a policy.json or tests.json list by its "per".
func (r renderer) items(list []map[string]any, what string) (out []map[string]any, skipped, reposItems []string, err error) {
	for _, item := range list {
		per, _ := item["per"].(string)
		base, _ := item["id"].(string)
		raw, err := json.Marshal(item)
		if err != nil {
			return nil, nil, nil, err
		}
		usesRepos := strings.Contains(string(raw), "{{repos}}")
		one := func(id, repo string) error {
			v, err := r.walk(item, repo, false)
			if err != nil {
				return fmt.Errorf("%s %s: %w", what, base, err)
			}
			m := v.(map[string]any)
			delete(m, "per")
			m["id"] = id
			out = append(out, m)
			return nil
		}
		switch per {
		case "org":
			if usesRepos {
				reposItems = append(reposItems, base)
			}
			err = one(base, "")
		case "repo":
			if !r.declared(kindRepository) {
				return nil, nil, nil, fmt.Errorf("%s %s: per repo needs the repository placeholder declared", what, base)
			}
			for _, repo := range r.o.repos {
				if err = one(repoRuleID(base, repo), repo); err != nil {
					break
				}
			}
		case "agent":
			// For the template's agent only, through the run the server
			// records for each action (`run.agent_id`).
			if r.o.agent == "" {
				skipped = append(skipped, base)
				continue
			}
			err = one(base+"--"+r.o.agent, "")
		default:
			err = fmt.Errorf("%s %s: per must be org, repo or agent", what, base)
		}
		if err != nil {
			return nil, nil, nil, err
		}
	}
	return out, skipped, reposItems, nil
}

// checkValues checks every value the options give against its declared
// placeholder's pattern and kind.
func (r renderer) checkValues() error {
	for _, name := range slices.Sorted(func(yield func(string) bool) {
		for k := range r.spec {
			if !yield(k) {
				return
			}
		}
	}) {
		p := r.spec[name]
		check, ok := placeholderKinds[name]
		if !ok || p.Kind != name {
			return fmt.Errorf("template %s: placeholder %q has unknown kind %q", r.o.name, name, p.Kind)
		}
		re, err := regexp.Compile(p.Pattern)
		if err != nil || p.Pattern == "" || !strings.HasPrefix(p.Pattern, "^") || !strings.HasSuffix(p.Pattern, "$") {
			return fmt.Errorf("template %s: placeholder %q needs an anchored pattern", r.o.name, name)
		}
		var values []string
		switch name {
		case kindRepository:
			values = r.o.repos
		case kindDefaultBranch:
			for _, repo := range r.o.repos {
				values = append(values, r.o.defaults[repo])
			}
		case kindEnvironment:
			values = []string{r.o.environment}
		case kindEnvironmentID:
			values = []string{r.o.environmentID}
		case kindWorkspace:
			values = []string{r.o.workspace}
		case kindAgent:
			values = []string{r.o.agent}
		case kindTimeZone:
			values = []string{r.o.timeZone}
		}
		for _, v := range values {
			if v == "" {
				continue // checked where it is needed
			}
			if !re.MatchString(v) {
				return fmt.Errorf("%s: %q does not match %s", placeholderFlags[name], v, p.Pattern)
			}
			if err := check(v); err != nil {
				return fmt.Errorf("%s: %q is %w", placeholderFlags[name], v, err)
			}
		}
	}
	return nil
}

// renderTemplate reads the template's files and fills in the options.
func renderTemplate(o templateOptions) (templateData, error) {
	var out templateData
	info, err := readTemplateInfo(o.name)
	if err != nil {
		return out, err
	}
	r := renderer{o: o, spec: info.Placeholders}
	if err := r.checkValues(); err != nil {
		return out, err
	}
	read := func(file string, into any, optional bool) (bool, error) {
		raw, err := fs.ReadFile(templates.FS, o.name+"/"+file)
		if errors.Is(err, fs.ErrNotExist) && optional {
			return false, nil
		} else if err != nil {
			return false, fmt.Errorf("template %s/%s: %w", o.name, file, err)
		}
		if err := json.Unmarshal(raw, into); err != nil {
			return false, fmt.Errorf("template %s/%s: %w", o.name, file, err)
		}
		return true, nil
	}
	// renderFile reads a file of guardrails and fills it in.
	renderFile := func(file string, into any, optional bool) (bool, error) {
		var v any
		ok, err := read(file, &v, optional)
		if !ok || err != nil {
			return ok, err
		}
		if v, err = r.walk(v, "", false); err != nil {
			return false, fmt.Errorf("template %s/%s: %w", o.name, file, err)
		}
		b, err := json.Marshal(v, json.Deterministic(true))
		if err != nil {
			return false, err
		}
		return true, json.Unmarshal(b, into)
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
	var tests struct {
		Tests []map[string]any `json:"tests"`
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
	if out.Envelope.Present, err = renderFile("envelope.json", &env, true); err != nil {
		return out, err
	}
	if _, err := renderFile("grant.json", &grant, false); err != nil {
		return out, err
	}
	hasWindow, err := renderFile("window.json", &window, true)
	if err != nil {
		return out, err
	}
	if _, err := read("policy.json", &policy, false); err != nil {
		return out, err
	}
	if _, err := read("tests.json", &tests, true); err != nil {
		return out, err
	}
	var skipped, more []string
	if out.Rules, out.Skipped, out.ReposItems, err = r.items(policy.Rules, "rule"); err != nil {
		return out, fmt.Errorf("template %s: %w", o.name, err)
	}
	if out.Tests, skipped, more, err = r.items(tests.Tests, "test"); err != nil {
		return out, fmt.Errorf("template %s: %w", o.name, err)
	}
	out.Skipped = append(out.Skipped, skipped...)
	out.PerRepo = slices.ContainsFunc(policy.Rules, func(r map[string]any) bool { return r["per"] == "repo" })
	out.ReposItems = append(out.ReposItems, more...)
	out.Info, out.TaskRef, out.Envelope.Name = info, info.TaskRef, env.Name
	if out.Envelope.Bounds, err = json.Marshal(env.Bounds, json.Deterministic(true)); err != nil {
		return out, err
	}
	if out.Grant.Bounds, err = json.Marshal(grant.Bounds, json.Deterministic(true)); err != nil {
		return out, err
	}
	if out.Grant.Limits, err = json.Marshal(grant.Limits, json.Deterministic(true)); err != nil {
		return out, err
	}
	if hasWindow {
		out.Window = &pantherclawv1.CreateChangeWindowRequest{Environment: window.Environment, TimeZone: window.TimeZone}
		for _, w := range window.Weekly {
			out.Window.Weekly = append(out.Window.Weekly, &pantherclawv1.WeeklyEntry{Day: w.Day, Start: w.Start, Minutes: w.Minutes})
		}
	}
	return out, nil
}

// resolveEnvironment sets o.environmentID when the template needs it: the
// one live environment whose slug is o.environment, preferring the --team
// scope's own, then the org's.
func resolveEnvironment(ctx context.Context, c clients, o *templateOptions) error {
	info, err := readTemplateInfo(o.name)
	if err != nil {
		return err
	}
	if _, ok := info.Placeholders[kindEnvironmentID]; !ok || o.environmentID != "" {
		return nil
	}
	var found []*pantherclawv1.Environment
	for token := ""; ; {
		res, err := c.tenancy.ListEnvironments(ctx, &pantherclawv1.ListEnvironmentsRequest{PageSize: 200, PageToken: token})
		if err != nil {
			return fmt.Errorf("reading the environments: %s", describe(err))
		}
		for _, e := range res.GetEnvironments() {
			if e.GetSlug() == o.environment && e.GetState() != pantherclawv1.EntityState_ENTITY_STATE_ARCHIVED {
				found = append(found, e)
			}
		}
		if token = res.GetNextPageToken(); token == "" {
			break
		}
	}
	if len(found) > 1 {
		found = slices.DeleteFunc(found, func(e *pantherclawv1.Environment) bool { return e.GetTeamId() != o.team })
	}
	switch len(found) {
	case 0:
		return fmt.Errorf("--environment: no environment %q (pclaw env list)", o.environment)
	case 1:
		o.environmentID = found[0].GetId()
		return nil
	}
	return fmt.Errorf("--environment: %d environments are named %q; pass --team for a team's", len(found), o.environment)
}

// errNeedsEnvironmentID: the template uses the environment's id, which is
// read from the server (resolveEnvironment).
var errNeedsEnvironmentID = errors.New("the environment's id is read from the server")

// approvalRoles are the roles the rules' approvals name, sorted.
func approvalRoles(rules []map[string]any) []string {
	var roles []string
	for _, r := range rules {
		a, _ := r["approval"].(map[string]any)
		if role, _ := a["role"].(string); role != "" && !slices.Contains(roles, role) {
			roles = append(roles, role)
		}
	}
	slices.Sort(roles)
	return roles
}

// sameValue reports whether a published rule or test is the template's.
func sameValue(have any, want map[string]any) bool { return reflect.DeepEqual(have, any(want)) }

// union is the sorted union of two lists of repositories.
func union(a, b []string) []string {
	out := slices.Clone(a)
	for _, x := range b {
		if !slices.Contains(out, x) {
			out = append(out, x)
		}
	}
	slices.Sort(out)
	return out
}

// repoLiteralRe finds the repositories a {{repos}} list names.
var repoLiteralRe = regexp.MustCompile(`'([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)'`)

// itemByID finds a rule or test by id in a bundle's list.
func itemByID(list []any, id string) map[string]any {
	for _, x := range list {
		if m, _ := x.(map[string]any); m["id"] == id {
			return m
		}
	}
	return nil
}

// renderedByID finds a rendered rule or test by id.
func renderedByID(d templateData, id string) map[string]any {
	for _, m := range slices.Concat(d.Rules, d.Tests) {
		if m["id"] == id {
			return m
		}
	}
	return nil
}

// appliedRepos are the repositories the published bundle's rules and
// tests over every repository ({{repos}}) name. Each must be exactly the
// template's rendering over the repositories it names, so a list a person
// changed by hand is never silently rewritten.
func appliedRepos(bundle map[string]any, o templateOptions, d templateData) ([]string, error) {
	rules, _ := bundle["rules"].([]any)
	tests, _ := bundle["tests"].([]any)
	var found []string
	for _, id := range d.ReposItems {
		cur := itemByID(slices.Concat(rules, tests), id)
		if cur == nil {
			continue
		}
		raw, err := json.Marshal(cur)
		if err != nil {
			return nil, err
		}
		var repos []string
		for _, m := range repoLiteralRe.FindAllStringSubmatch(string(raw), -1) {
			repos = union(repos, []string{m[1]})
		}
		check := o
		check.repos, check.defaults = repos, map[string]string{}
		for _, r := range repos {
			check.defaults[r] = "main"
		}
		cd, err := renderTemplate(check)
		if len(repos) == 0 || err != nil || !sameValue(cur, renderedByID(cd, id)) {
			return nil, fmt.Errorf("%s was changed since the template made it; pass --update to replace it with the template's for --repos only", id)
		}
		found = union(found, repos)
	}
	return found, nil
}

// renderOver replaces d's rules and tests over every repository with their
// rendering for wide's repositories.
func renderOver(d templateData, wide templateOptions) (templateData, error) {
	w, err := renderTemplate(wide)
	if err != nil {
		return d, err
	}
	swap := func(items []map[string]any) []map[string]any {
		out := slices.Clone(items)
		for i, it := range out {
			if id, _ := it["id"].(string); slices.Contains(d.ReposItems, id) {
				out[i] = renderedByID(w, id)
			}
		}
		return out
	}
	d.Rules, d.Tests = swap(d.Rules), swap(d.Tests)
	return d, nil
}
