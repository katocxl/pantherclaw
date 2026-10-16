// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"reflect"
	"regexp"
	"slices"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/policy/packs/render"
)

// Rendering a template (G0 M8 C4; M11.1 D16 and D27) is
// internal/policy/packs/render's, shared with the server's reference packs
// (G0 M11 part 2, D41): placeholders are declared with a kind and a
// pattern, checked, and quoted as CEL string literals in conditions.

// placeholderSpec is one declared placeholder.
type placeholderSpec = render.Spec

// Placeholder kinds; a template's placeholder is named after its kind.
const (
	kindRepository    = render.KindRepository
	kindDefaultBranch = render.KindDefaultBranch
	kindEnvironment   = render.KindEnvironment
	kindEnvironmentID = render.KindEnvironmentID
	kindWorkspace     = render.KindWorkspace
	kindAgent         = render.KindAgent
	kindTimeZone      = render.KindTimeZone
)

// otherEnvironmentID is {{other_environment_id}}.
const otherEnvironmentID = render.OtherEnvironmentID

// celQuote is s as a CEL string literal.
func celQuote(s string) string { return render.CELQuote(s) }

// repoRuleID is a per-repository rule's id.
func repoRuleID(base, repo string) string { return render.RepoRuleID(base, repo) }

// templateData is a template rendered for its options.
type templateData struct {
	render.Data
	Info templateInfo
	// Window is nil when the template sets none.
	Window *pantherclawv1.CreateChangeWindowRequest
}

// renderOptions are o as the renderer takes them.
func (o templateOptions) renderOptions() render.Options {
	return render.Options{
		Name: o.name, Repos: o.repos, Defaults: o.defaults, Agent: o.agent, Environment: o.environment,
		EnvironmentID: o.environmentID, Workspace: o.workspace, TimeZone: o.timeZone,
	}
}

// renderer fills one template's placeholders for its options.
type renderer struct {
	o    templateOptions
	spec map[string]placeholderSpec
}

// fill replaces the placeholders in s.
func (r renderer) fill(s, repo string, cel bool) (string, error) {
	return render.Renderer{O: r.o.renderOptions(), Spec: r.spec}.Fill(s, repo, cel)
}

// renderTemplate reads the template's files and fills in the options.
func renderTemplate(o templateOptions) (templateData, error) {
	var out templateData
	info, err := readTemplateInfo(o.name)
	if err != nil {
		return out, err
	}
	if out.Data, err = render.Render(o.renderOptions()); err != nil {
		return out, err
	}
	out.Info = info
	if w := out.Data.Window; w != nil {
		out.Window = &pantherclawv1.CreateChangeWindowRequest{Environment: w.Environment, TimeZone: w.TimeZone}
		for _, e := range w.Weekly {
			out.Window.Weekly = append(out.Window.Weekly, &pantherclawv1.WeeklyEntry{Day: e.Day, Start: e.Start, Minutes: e.Minutes})
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
var errNeedsEnvironmentID = render.ErrNeedsEnvironmentID

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
