// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"slices"
	"strings"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/templates"
)

// pclaw template remove (G0 M8 C4, the coordinator's decision Q8): takes a
// template's per-repository rules and tests away for the named
// repositories, or a template without repositories away entirely, as a
// person, through the policy APIs (audited there). Removing a repository is
// never a side effect of applying the template for others; a rule over
// every repository the template was applied for keeps the others. A
// repository a live grant from the template still covers keeps its rules:
// the grant is revised or revoked first, so no grant outlives the rules
// that hold it. Removing rules loosens the policy, so the new version
// waits for confirmations (M11.1 D6, D16).

func init() {
	commands["template remove"] = command{
		usage: "template remove NAME [--repos OWNER/REPO[,OWNER/REPO…]] [--dry-run] [--yes]",
		run:   templateRemove,
	}
}

// templateItemIDs are the ids of a template's rules and tests for the
// repositories in o (per repo), or its org items (per org); agent items
// stay, as apply leaves them to the agent's grant.
func templateItemIDs(o templateOptions) (rules, tests, orgRules, orgTests []string, err error) {
	ids := func(file, key string) (repo, org []string, err error) {
		raw, err := fs.ReadFile(templates.FS, o.name+"/"+file)
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, nil
		} else if err != nil {
			return nil, nil, err
		}
		var doc map[string][]map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, nil, fmt.Errorf("template %s/%s: %w", o.name, file, err)
		}
		for _, item := range doc[key] {
			base, _ := item["id"].(string)
			switch item["per"] {
			case "repo":
				for _, r := range o.repos {
					repo = append(repo, repoRuleID(base, r))
				}
			case "org":
				org = append(org, base)
			}
		}
		return repo, org, nil
	}
	if rules, orgRules, err = ids("policy.json", "rules"); err != nil {
		return
	}
	tests, orgTests, err = ids("tests.json", "tests")
	return
}

func templateRemove(ctx context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("template remove", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	repos := fs.String("repos", "", "the GitHub repositories, owner/repo, comma-separated")
	o := templateOptions{environment: "production", timeZone: "UTC"}
	fs.BoolVar(&o.dryRun, "dry-run", false, "show the plan and change nothing")
	fs.BoolVar(&o.yes, "yes", false, "remove without asking")
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return errUsage
	}
	o.name = args[0]
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
		return errUsage
	}
	info, err := readTemplateInfo(o.name)
	if err != nil {
		return err
	}
	_, perRepo := info.Placeholders[kindRepository]
	o.defaults = map[string]string{}
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
		o.defaults[r] = "main" // the rule ids do not depend on it
	}
	switch {
	case perRepo && len(o.repos) == 0:
		return errors.New("--repos names no repository")
	case !perRepo && len(o.repos) > 0:
		return fmt.Errorf("template %s takes no --repos", o.name)
	}
	slices.Sort(o.repos)
	ruleIDs, testIDs, orgRules, orgTests, err := templateItemIDs(o)
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
		return errors.New("a template is removed by a person, signed in with pclaw login")
	}
	bundle, planned, err := publishedBundle(ctx, c)
	if err != nil {
		return err
	}
	rules, _ := bundle["rules"].([]any)
	tests, _ := bundle["tests"].([]any)

	// The org items go with the template's last repository (or with the
	// template, when it has none); a rule over every repository is
	// rendered again for the repositories that stay.
	var updated []string
	if !perRepo {
		ruleIDs, testIDs = append(ruleIDs, orgRules...), append(testIDs, orgTests...)
	} else if len(orgRules)+len(orgTests) > 0 {
		all := o
		all.repos = nil
		d, err := renderTemplate(withRepos(o, o.repos))
		if err != nil {
			return err
		}
		applied, err := appliedRepos(bundle, all, d)
		if err != nil {
			return err
		}
		left := slices.DeleteFunc(slices.Clone(applied), func(r string) bool { return slices.Contains(o.repos, r) })
		switch {
		case len(applied) == 0:
		case len(left) == 0:
			ruleIDs, testIDs = append(ruleIDs, orgRules...), append(testIDs, orgTests...)
		default:
			w, err := renderTemplate(withRepos(o, left))
			if err != nil {
				return err
			}
			for _, id := range w.ReposItems {
				if i := slices.IndexFunc(rules, func(r any) bool { m, _ := r.(map[string]any); return m["id"] == id }); i >= 0 {
					rules[i], updated = renderedByID(w, id), append(updated, id)
				}
				if i := slices.IndexFunc(tests, func(r any) bool { m, _ := r.(map[string]any); return m["id"] == id }); i >= 0 {
					tests[i], updated = renderedByID(w, id), append(updated, id)
				}
			}
		}
	}
	var removed, removedTests []string
	drop := func(list []any, ids []string, into *[]string) []any {
		return slices.DeleteFunc(list, func(r any) bool {
			m, _ := r.(map[string]any)
			id, _ := m["id"].(string)
			if slices.Contains(ids, id) {
				*into = append(*into, id)
				return true
			}
			return false
		})
	}
	rules, tests = drop(rules, ruleIDs, &removed), drop(tests, testIDs, &removedTests)

	var holding []string
	for token := ""; ; {
		res, err := c.grants.ListGrants(ctx, &pantherclawv1.ListGrantsRequest{PageSize: 200, PageToken: token, State: pantherclawv1.GrantState_GRANT_STATE_ACTIVE})
		if err != nil {
			return err
		}
		for _, g := range res.GetGrants() {
			if g.GetTaskRef() != info.TaskRef {
				continue
			}
			if !perRepo {
				holding = append(holding, fmt.Sprintf("grant %s (agent %s) is the template's", g.GetId(), g.GetAgentId()))
			}
			for _, r := range o.repos {
				if boundsName(g.GetBounds(), r) {
					holding = append(holding, fmt.Sprintf("grant %s (agent %s) still covers %s", g.GetId(), g.GetAgentId(), r))
				}
			}
		}
		if token = res.GetNextPageToken(); token == "" {
			break
		}
	}

	w := a.stdout
	if perRepo {
		_, _ = fmt.Fprintf(w, "Template %s, removing %s, as %s:\n", o.name, strings.Join(o.repos, ", "), me.GetPrincipal().GetDisplayName())
	} else {
		_, _ = fmt.Fprintf(w, "Template %s, removing it, as %s:\n", o.name, me.GetPrincipal().GetDisplayName())
	}
	for _, id := range ruleIDs {
		state := "absent"
		if slices.Contains(removed, id) {
			state = "remove"
		}
		_, _ = fmt.Fprintf(w, "  %-9s policy rule %s\n", state, id)
	}
	for _, id := range updated {
		_, _ = fmt.Fprintf(w, "  %-9s policy rule %s, for the repositories that stay\n", stepUpdate, id)
	}
	if len(removedTests) > 0 {
		_, _ = fmt.Fprintf(w, "  and the template's %d scenario tests for them\n", len(removedTests))
	}
	_, _ = fmt.Fprintln(w, "  Keeps the change window, the envelopes, the agent's rules and every grant.")
	for _, h := range holding {
		_, _ = fmt.Fprintf(w, "  %s: revise or revoke it first.\n", h)
	}
	changes := len(removed) + len(updated)
	switch {
	case len(holding) > 0:
		return errors.New("live grants from the template still cover what it protects (shown above); nothing was changed")
	case changes == 0:
		_, _ = fmt.Fprintln(w, "Nothing to remove.")
		return nil
	case o.dryRun:
		_, _ = fmt.Fprintln(w, "Dry run: nothing was changed.")
		return nil
	case !o.yes && !confirm(a, fmt.Sprintf("Remove these %d rule(s)?", len(removed))):
		return errors.New("nothing was changed")
	}
	bundle["rules"] = rules
	if len(tests) > 0 {
		bundle["tests"] = tests
	} else {
		delete(bundle, "tests")
	}
	done, err := publishBundle(c, bundle, planned, nil)(ctx)
	var wait *waitingError
	switch {
	case errors.As(err, &wait):
		// Removing rules loosens the policy (D3): it waits for people
		// holding policy.publish to confirm it.
		_, _ = fmt.Fprintf(w, "Waiting for confirmation: %s\n", wait.msg)
		return nil
	case err != nil:
		return fmt.Errorf("policy: %s (nothing was changed)", describe(err))
	}
	_, _ = fmt.Fprintf(w, "Done: %s\n", done)
	return nil
}

// withRepos is o for other repositories.
func withRepos(o templateOptions, repos []string) templateOptions {
	o.repos, o.defaults = repos, map[string]string{}
	for _, r := range repos {
		o.defaults[r] = "main"
	}
	return o
}

// boundsName reports whether grant bounds name a repository or one of its
// pull requests or branches.
func boundsName(bounds []byte, repo string) bool {
	var v any
	if json.Unmarshal(bounds, &v) != nil {
		return true // unreadable bounds are assumed to cover it
	}
	var walk func(any) bool
	walk = func(v any) bool {
		switch v := v.(type) {
		case map[string]any:
			for _, x := range v {
				if walk(x) {
					return true
				}
			}
		case []any:
			return slices.ContainsFunc(v, walk)
		case string:
			return v == repo || strings.HasPrefix(v, repo+"#") || strings.HasPrefix(v, repo+"@")
		}
		return false
	}
	return walk(v)
}
