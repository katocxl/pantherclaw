// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package render fills a policy template's placeholders (G0 M8 C4; M11.1
// D16 and D27): pclaw template apply renders templates on a person's
// machine, and reference packs (G0 M11 part 2, D41) render them on the
// server, both with this code.
//
// A template's template.json declares every placeholder its files use,
// each with a kind and a pattern. A value is checked against both before
// it is used, and a value that goes into a rule's condition is inserted
// only as a quoted CEL string literal (CELQuote), never pasted into the
// expression text. A placeholder the template does not declare is an
// error, so a template cannot use a value nobody checked.
//
// Rules and tests in policy.json and tests.json carry "per": "org" (once),
// "repo" (once per repository, its id made per repository) or "agent"
// (once for the agent, skipped without one).
package render

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"strings"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/templates"
)

// Spec is one declared placeholder.
type Spec struct {
	Kind    string `json:"kind"`
	Pattern string `json:"pattern"`
}

// Placeholder kinds; a template's placeholder is named after its kind.
const (
	KindRepository    = "repository"
	KindDefaultBranch = "default_branch"
	KindEnvironment   = "environment"
	KindEnvironmentID = "environment_id"
	KindWorkspace     = "workspace"
	KindAgent         = "agent"
	KindTimeZone      = "time_zone"
	// KindPayee is a Stripe connected account a template sends funds to
	// (G0 M14 D97): {{payees}} in a condition is the list of them, a list
	// item naming {{payee}} is repeated for each, and {{payee}} anywhere
	// else is the first (for tests).
	KindPayee = "payee"
)

var (
	// RepoRe is a GitHub repository as pc.github names targets.
	RepoRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,38}/\.?[a-z0-9_-][a-z0-9._-]{0,98}$`)
	// BranchRe is a branch name.
	BranchRe = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9._-]{0,99}(/[A-Za-z0-9_-][A-Za-z0-9._-]{0,99}){0,7}$`)
	// PayeeRe is a Stripe connected account as pc.stripe names targets.
	PayeeRe = regexp.MustCompile(`^acct_[A-Za-z0-9]{8,64}$`)
	uuidRe  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	nameRe  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
)

// kinds are the kinds and the checks a value of each must pass besides its
// declared pattern.
var kinds = map[string]func(string) error{
	KindRepository: func(v string) error {
		if !RepoRe.MatchString(v) {
			return errors.New("not a lowercase owner/repo")
		}
		return nil
	},
	KindDefaultBranch: func(v string) error {
		if !BranchRe.MatchString(v) {
			return errors.New("not a branch name")
		}
		return nil
	},
	KindEnvironment: func(string) error { return nil },
	KindEnvironmentID: func(v string) error {
		if !uuidRe.MatchString(v) {
			return errors.New("not an id")
		}
		return nil
	},
	KindWorkspace: func(v string) error {
		if n, err := actionir.NormalizePath(v); err != nil || n != v || !strings.HasPrefix(v, "/") {
			return errors.New("not a normalized absolute path")
		}
		return nil
	},
	KindAgent: func(v string) error {
		if !uuidRe.MatchString(v) {
			return errors.New("not an id")
		}
		return nil
	},
	KindTimeZone: func(string) error { return nil },
	KindPayee: func(v string) error {
		if !PayeeRe.MatchString(v) || v == OtherPayee {
			return errors.New("not a Stripe connected account (acct_...)")
		}
		return nil
	},
}

// Flags name the option each kind's value comes from in pclaw; Options
// carries other names for other callers.
var Flags = map[string]string{
	KindRepository: "--repos", KindDefaultBranch: "--default-branch", KindEnvironment: "--environment",
	KindEnvironmentID: "--environment", KindWorkspace: "--workspace", KindAgent: "--agent", KindTimeZone: "--time-zone", KindPayee: "--payee",
}

// OtherEnvironmentID is {{other_environment_id}}: an environment id that
// is never the template's, for tests that show a rule stays in its
// environment.
const OtherEnvironmentID = "00000000-0000-7000-8000-0000000000e9"

// OtherPayee is {{other_payee}}: a connected account that is never one of
// the template's payees, for tests that show a transfer elsewhere is
// refused. A payee named so is refused.
const OtherPayee = "acct_PantherClawNotAPayee"

// ErrNeedsEnvironmentID: the template uses the environment's id, which
// the caller resolves.
var ErrNeedsEnvironmentID = errors.New("the environment's id is read from the server")

// CELQuote is s as a CEL string literal. Values are checked against their
// patterns first; quoting is the second line, so a value can never end the
// literal and change the condition.
func CELQuote(s string) string {
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

// ruleIDMax is the longest policy rule id.
const ruleIDMax = 64

// RepoRuleID is a per-repository rule's id: c2p-<kind>--<owner>-<repo>-<6
// hex>, the owner and repository lowercased with anything outside [a-z0-9]
// turned into "-", and the hex from sha256 of the exact "owner/repo", so
// repositories that differ only in case or punctuation never share an id.
// A long name is cut, the hash kept.
func RepoRuleID(base, repo string) string {
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

// Options are the values a template is rendered with.
type Options struct {
	Name     string
	Repos    []string
	Defaults map[string]string // repository → default branch
	Agent    string
	// Environment is the environment's slug, EnvironmentID its id.
	Environment, EnvironmentID string
	Workspace, TimeZone        string
	// Payees are the connected accounts a template sends funds to.
	Payees []string
	// Names name each kind's value in errors (nil: Flags).
	Names map[string]string
}

func (o Options) name(kind string) string {
	if n, ok := o.Names[kind]; ok {
		return n
	}
	return Flags[kind]
}

// Weekly is one weekly entry of a change window.
type Weekly struct {
	Day     string `json:"day"`
	Start   string `json:"start"`
	Minutes int32  `json:"minutes"`
}

// Window is a template's change window.
type Window struct {
	Environment string   `json:"environment"`
	TimeZone    string   `json:"time_zone"`
	Weekly      []Weekly `json:"weekly"`
}

// Info is what rendering reads of a template's template.json.
type Info struct {
	TaskRef      string          `json:"task_ref"`
	Placeholders map[string]Spec `json:"placeholders"`
}

// Data is a template rendered for its options.
type Data struct {
	TaskRef      string
	Placeholders map[string]Spec
	Envelope     struct {
		Present bool
		Name    string
		Bounds  []byte
	}
	Grant struct {
		Bounds, Limits []byte
	}
	Rules []map[string]any
	Tests []map[string]any
	// Skipped are the agent rules left out for want of an agent (their
	// tests are left out with them).
	Skipped []string
	// Window is nil when the template sets none.
	Window *Window
	// PerRepo: some of its rules are per repository.
	PerRepo bool
	// ReposItems are the ids of the org rules and tests rendered over every
	// repository ({{repos}}).
	ReposItems []string
}

var placeholderRe = regexp.MustCompile(`\{\{([a-z_]+)\}\}`)

// Renderer fills one template's placeholders for its options.
type Renderer struct {
	O    Options
	Spec map[string]Spec
}

// declared reports whether the template declares a kind.
func (r Renderer) declared(kind string) bool { _, ok := r.Spec[kind]; return ok }

// value is a placeholder's text: a CEL expression or a quoted literal in a
// condition (cel), the bare value elsewhere. repo is the repository of a
// per-repository item.
func (r Renderer) value(name, repo string, cel bool) (string, error) {
	needRepo := func() error {
		if repo == "" {
			return fmt.Errorf("{{%s}} is used outside a per-repository item", name)
		}
		return nil
	}
	quote := func(s string) string {
		if cel {
			return CELQuote(s)
		}
		return s
	}
	macro := func() error {
		if !cel {
			return fmt.Errorf("{{%s}} is a condition and is used outside one", name)
		}
		if !r.declared(KindRepository) {
			return fmt.Errorf("{{%s}} needs the repository placeholder declared", name)
		}
		return nil
	}
	switch name {
	case "repo":
		if !r.declared(KindRepository) {
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
		return "action.target.id == " + CELQuote(repo), nil
	case "pull_request":
		if err := errors.Join(macro(), needRepo()); err != nil {
			return "", err
		}
		return "action.target.id.startsWith(" + CELQuote(repo+"#") + ")", nil
	case "default_ref":
		if err := errors.Join(macro(), needRepo()); err != nil {
			return "", err
		}
		if !r.declared(KindDefaultBranch) {
			return "", errors.New("{{default_ref}} needs the default_branch placeholder declared")
		}
		return "action.target.id == " + CELQuote(repo+"@refs/heads/"+r.O.Defaults[repo]), nil
	case "repos":
		if err := macro(); err != nil {
			return "", err
		}
		q := make([]string, len(r.O.Repos))
		for i, x := range r.O.Repos {
			q[i] = CELQuote(x)
		}
		return "[" + strings.Join(q, ", ") + "]", nil
	case "payees":
		if !cel {
			return "", errors.New("{{payees}} is a condition and is used outside one")
		}
		if !r.declared(KindPayee) {
			return "", errors.New("{{payees}} needs the payee placeholder declared")
		}
		q := make([]string, len(r.O.Payees))
		for i, x := range r.O.Payees {
			q[i] = CELQuote(x)
		}
		return "[" + strings.Join(q, ", ") + "]", nil
	case "other_payee":
		if r.declared(KindPayee) {
			return quote(OtherPayee), nil
		}
	case "other_environment_id":
		if r.declared(KindEnvironmentID) {
			return quote(OtherEnvironmentID), nil
		}
	}
	if !r.declared(name) || name == KindRepository {
		return "", fmt.Errorf("{{%s}} is not a declared placeholder", name)
	}
	var v string
	switch name {
	case KindDefaultBranch:
		if err := needRepo(); err != nil {
			return "", err
		}
		v = r.O.Defaults[repo]
	case KindEnvironment:
		v = r.O.Environment
	case KindEnvironmentID:
		v = r.O.EnvironmentID
	case KindWorkspace:
		v = r.O.Workspace
	case KindAgent:
		v = r.O.Agent
	case KindTimeZone:
		v = r.O.TimeZone
	case KindPayee:
		if len(r.O.Payees) > 0 {
			v = r.O.Payees[0]
		}
	}
	switch {
	case v == "" && name == KindEnvironmentID:
		return "", ErrNeedsEnvironmentID
	case v == "":
		return "", fmt.Errorf("{{%s}} needs %s", name, r.O.name(name))
	}
	return quote(v), nil
}

// Fill replaces the placeholders in s.
func (r Renderer) Fill(s, repo string, cel bool) (string, error) {
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
func (r Renderer) walk(v any, repo string, when bool) (any, error) {
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
				for _, each := range r.O.Repos {
					y, err := r.Fill(s, each, false)
					if err != nil {
						return nil, err
					}
					out = append(out, y)
				}
				continue
			}
			if s, ok := x.(string); ok && r.declared(KindPayee) && strings.Contains(s, "{{payee}}") {
				for _, each := range r.O.Payees {
					y, err := r.Fill(strings.ReplaceAll(s, "{{payee}}", each), repo, false)
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
		return r.Fill(v, repo, when)
	}
	return v, nil
}

// items renders a policy.json or tests.json list by its "per".
func (r Renderer) items(list []map[string]any, what string) (out []map[string]any, skipped, reposItems []string, err error) {
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
			if !r.declared(KindRepository) {
				return nil, nil, nil, fmt.Errorf("%s %s: per repo needs the repository placeholder declared", what, base)
			}
			for _, repo := range r.O.Repos {
				if err = one(RepoRuleID(base, repo), repo); err != nil {
					break
				}
			}
		case "agent":
			// For the template's agent only, through the run the server
			// records for each action (`run.agent_id`).
			if r.O.Agent == "" {
				skipped = append(skipped, base)
				continue
			}
			err = one(base+"--"+r.O.Agent, "")
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
func (r Renderer) checkValues() error {
	for _, name := range slices.Sorted(func(yield func(string) bool) {
		for k := range r.Spec {
			if !yield(k) {
				return
			}
		}
	}) {
		p := r.Spec[name]
		check, ok := kinds[name]
		if !ok || p.Kind != name {
			return fmt.Errorf("template %s: placeholder %q has unknown kind %q", r.O.Name, name, p.Kind)
		}
		re, err := regexp.Compile(p.Pattern)
		if err != nil || p.Pattern == "" || !strings.HasPrefix(p.Pattern, "^") || !strings.HasSuffix(p.Pattern, "$") {
			return fmt.Errorf("template %s: placeholder %q needs an anchored pattern", r.O.Name, name)
		}
		var values []string
		switch name {
		case KindRepository:
			values = r.O.Repos
		case KindDefaultBranch:
			for _, repo := range r.O.Repos {
				values = append(values, r.O.Defaults[repo])
			}
		case KindEnvironment:
			values = []string{r.O.Environment}
		case KindEnvironmentID:
			values = []string{r.O.EnvironmentID}
		case KindWorkspace:
			values = []string{r.O.Workspace}
		case KindAgent:
			values = []string{r.O.Agent}
		case KindTimeZone:
			values = []string{r.O.TimeZone}
		case KindPayee:
			if len(r.O.Payees) == 0 {
				return fmt.Errorf("template %s needs %s", r.O.Name, r.O.name(name))
			}
			values = r.O.Payees
		}
		for _, v := range values {
			if v == "" {
				continue // checked where it is needed
			}
			if !re.MatchString(v) {
				return fmt.Errorf("%s: %q does not match %s", r.O.name(name), v, p.Pattern)
			}
			if err := check(v); err != nil {
				return fmt.Errorf("%s: %q is %w", r.O.name(name), v, err)
			}
		}
	}
	return nil
}

// ReadInfo reads what rendering needs of a template's template.json.
func ReadInfo(name string) (Info, error) {
	var info Info
	if !nameRe.MatchString(name) {
		return info, fmt.Errorf("no template %q", name)
	}
	raw, err := fs.ReadFile(templates.FS, name+"/template.json")
	if errors.Is(err, fs.ErrNotExist) {
		return info, fmt.Errorf("no template %q", name)
	} else if err != nil {
		return info, err
	}
	if err := json.Unmarshal(raw, &info); err != nil {
		return info, fmt.Errorf("template %s/template.json: %w", name, err)
	}
	return info, nil
}

// Render reads the template's files and fills in the options.
func Render(o Options) (Data, error) {
	var out Data
	info, err := ReadInfo(o.Name)
	if err != nil {
		return out, err
	}
	r := Renderer{O: o, Spec: info.Placeholders}
	if err := r.checkValues(); err != nil {
		return out, err
	}
	read := func(file string, into any, optional bool) (bool, error) {
		raw, err := fs.ReadFile(templates.FS, o.Name+"/"+file)
		if errors.Is(err, fs.ErrNotExist) && optional {
			return false, nil
		} else if err != nil {
			return false, fmt.Errorf("template %s/%s: %w", o.Name, file, err)
		}
		if err := json.Unmarshal(raw, into); err != nil {
			return false, fmt.Errorf("template %s/%s: %w", o.Name, file, err)
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
			return false, fmt.Errorf("template %s/%s: %w", o.Name, file, err)
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
	var window Window
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
	var more []string
	if out.Rules, out.Skipped, out.ReposItems, err = r.items(policy.Rules, "rule"); err != nil {
		return out, fmt.Errorf("template %s: %w", o.Name, err)
	}
	if out.Tests, _, more, err = r.items(tests.Tests, "test"); err != nil {
		return out, fmt.Errorf("template %s: %w", o.Name, err)
	}
	out.PerRepo = slices.ContainsFunc(policy.Rules, func(r map[string]any) bool { return r["per"] == "repo" })
	out.ReposItems = append(out.ReposItems, more...)
	out.TaskRef, out.Placeholders, out.Envelope.Name = info.TaskRef, info.Placeholders, env.Name
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
		out.Window = &window
	}
	return out, nil
}
