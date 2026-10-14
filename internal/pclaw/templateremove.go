// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"slices"
	"strings"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// pclaw template remove (G0 M8 C4, the coordinator's decision Q8): takes a
// template's per-repository rules away for the named repositories, as a
// person, through the policy APIs (audited there). Removing a repository is
// never a side effect of applying the template for others. A repository a
// live grant from the template still covers keeps its rules: the grant is
// revised or revoked first, so no grant outlives the rules that hold it.

func init() {
	commands["template remove"] = command{
		usage: "template remove NAME --repos OWNER/REPO[,OWNER/REPO…] [--dry-run] [--yes]",
		run:   templateRemove,
	}
}

func templateRemove(ctx context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("template remove", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	repos := fs.String("repos", "", "the GitHub repositories, owner/repo, comma-separated")
	var o templateOptions
	fs.BoolVar(&o.dryRun, "dry-run", false, "show the plan and change nothing")
	fs.BoolVar(&o.yes, "yes", false, "remove without asking")
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return errUsage
	}
	o.name = args[0]
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
		return errUsage
	}
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
	if len(o.repos) == 0 {
		return errors.New("--repos names no repository")
	}
	slices.Sort(o.repos)
	data, err := renderTemplate(o) // no agent: the per-repository rules only
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
	var removed []string
	rules = slices.DeleteFunc(rules, func(r any) bool {
		m, _ := r.(map[string]any)
		id, _ := m["id"].(string)
		if slices.ContainsFunc(data.Rules, func(t map[string]any) bool { return t["id"] == id }) {
			removed = append(removed, id)
			return true
		}
		return false
	})
	var holding []string
	for token := ""; ; {
		res, err := c.grants.ListGrants(ctx, &pantherclawv1.ListGrantsRequest{PageSize: 200, PageToken: token, State: pantherclawv1.GrantState_GRANT_STATE_ACTIVE})
		if err != nil {
			return err
		}
		for _, g := range res.GetGrants() {
			for _, r := range o.repos {
				if g.GetTaskRef() == data.TaskRef && boundsName(g.GetBounds(), r) {
					holding = append(holding, fmt.Sprintf("grant %s (agent %s) still covers %s", g.GetId(), g.GetAgentId(), r))
				}
			}
		}
		if token = res.GetNextPageToken(); token == "" {
			break
		}
	}

	w := a.stdout
	_, _ = fmt.Fprintf(w, "Template %s, removing %s, as %s:\n", o.name, strings.Join(o.repos, ", "), me.GetPrincipal().GetDisplayName())
	for _, t := range data.Rules {
		state := "absent"
		if slices.Contains(removed, t["id"].(string)) {
			state = "remove"
		}
		_, _ = fmt.Fprintf(w, "  %-9s policy rule %s\n", state, t["id"])
	}
	_, _ = fmt.Fprintln(w, "  Keeps the change window, the envelopes, the shell rules and every grant.")
	for _, h := range holding {
		_, _ = fmt.Fprintf(w, "  %s: revise or revoke it first.\n", h)
	}
	switch {
	case len(holding) > 0:
		return errors.New("live grants from the template still cover these repositories (shown above); nothing was changed")
	case len(removed) == 0:
		_, _ = fmt.Fprintln(w, "Nothing to remove.")
		return nil
	case o.dryRun:
		_, _ = fmt.Fprintln(w, "Dry run: nothing was changed.")
		return nil
	case !o.yes && !confirm(a, fmt.Sprintf("Remove these %d rule(s)?", len(removed))):
		return errors.New("nothing was changed")
	}
	bundle["rules"] = rules
	done, err := publishBundle(c, bundle, planned, nil)(ctx)
	if err != nil {
		return fmt.Errorf("policy: %s (nothing was changed)", describe(err))
	}
	_, _ = fmt.Fprintf(w, "Done: %s\n", done)
	return nil
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
