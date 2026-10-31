// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/hub/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	policyapp "github.com/katocxl/pantherclaw/internal/policy/app"
	"github.com/katocxl/pantherclaw/internal/policy/packs"
	"github.com/katocxl/pantherclaw/internal/policy/packs/render"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// The ports, one per kind that installs on a server (D104). Each is the
// kind's own use case, with its own permission and edition checks.
type (
	// PolicyDrafts stores a DRAFT policy version, as `template apply` does
	// before it publishes.
	PolicyDrafts interface {
		Published(ctx context.Context) (*policyapp.VersionInfo, error)
		CreateExpectingWith(ctx context.Context, raw []byte, expected *ids.UUID, details map[string]string) (policyapp.VersionInfo, error)
		// FindDraft returns a DRAFT version holding this bundle.
		FindDraft(ctx context.Context, raw []byte) (string, bool, error)
	}
	// DetectionDrafts stores a DRAFT custom rule and returns its id
	// (Business, as CreateCustomRule is).
	DetectionDrafts interface {
		CreateDraft(ctx context.Context, content string) (string, error)
		// FindDraft returns a custom rule with exactly this content.
		FindDraft(ctx context.Context, content string) (string, bool, error)
	}
	// AutomationDrafts creates a DRAFT automation with its first DRAFT
	// version, owned by the caller, and returns its id.
	AutomationDrafts interface {
		CreateDraft(ctx context.Context, b domain.AutomationBody) (string, error)
		// FindDraft returns the automation of this name with a version of
		// exactly this definition.
		FindDraft(ctx context.Context, b domain.AutomationBody) (string, bool, error)
	}
	// PackageImports is ImportPackage, unchanged: the package root's
	// signature is checked, and the version starts REVIEWED.
	PackageImports interface {
		ImportPackage(ctx context.Context, name, version, targets string, raw []byte) error
	}
)

// result is what a route made.
type result struct {
	kind, ref string
	skipped   []string
	replaced  []string
}

// draft is how an item reaches its kind's use case: create makes the draft,
// and find, on a reclaimed install, looks for the one a crashed install left.
type draft struct {
	create func(context.Context) (result, error)
	find func(context.Context) (result, bool, error)
}

// prepare checks what can be checked without writing, and returns what makes
// the item's draft. Nothing here activates, publishes or enables anything
// (HR-561).
func (s *Service) prepare(ctx context.Context, c tapp.Caller, e domain.Entry, it domain.Item, params map[string]string) (draft, error) {
	body, err := it.DecodeBody()
	if err != nil {
		return draft{}, err
	}
	details := map[string]string{"hub_item": e.Name + "@" + e.Version, "hub_item_sha256": e.SHA256}
	switch b := body.(type) {
	case domain.PolicyTemplateBody:
		return s.policyRoute(ctx, c, it, b, params, details)
	case domain.DetectionRuleBody:
		return draft{
			create: func(ctx context.Context) (result, error) {
				id, err := s.Detections.CreateDraft(ctx, b.Content)
				return result{kind: ResultCustomRule, ref: id}, err
			},
			find: func(ctx context.Context) (result, bool, error) {
				id, ok, err := s.Detections.FindDraft(ctx, b.Content)
				return result{kind: ResultCustomRule, ref: id}, ok, err
			},
		}, nil
	case domain.AutomationBody:
		return draft{
			create: func(ctx context.Context) (result, error) {
				id, err := s.Automations.CreateDraft(ctx, b)
				return result{kind: ResultAutomation, ref: id}, err
			},
			find: func(ctx context.Context) (result, bool, error) {
				id, ok, err := s.Automations.FindDraft(ctx, b)
				return result{kind: ResultAutomation, ref: id}, ok, err
			},
		}, nil
	case domain.ToolPackageBody:
		raw := []byte(b.PackageYAML)
		p, err := manifest.Decode(raw)
		if err != nil {
			return draft{}, fmt.Errorf("%w: package_yaml: %w", domain.ErrItem, err)
		}
		// The index cannot list one thing and install another.
		if p.Name != e.Name || p.Version != e.Version {
			return draft{}, fmt.Errorf("%w: package_yaml is %s@%s, listed as %s@%s", domain.ErrItem, p.Name, p.Version, e.Name, e.Version)
		}
		// No find: importing the same file again changes nothing.
		return draft{create: func(ctx context.Context) (result, error) {
			err := s.Packages.ImportPackage(ctx, p.Name, p.Version, b.TargetsJWS, raw)
			return result{kind: ResultPackageVersion, ref: p.Name + "@" + p.Version}, err
		}}, nil
	}
	return draft{}, errors.New("hub: no route for this kind")
}

// maxBundleItems bounds the rules or tests of a bundle, as a pack's does.
const maxBundleItems = 512

// policyRoute renders the template with the params, merges its rules and
// tests into the published policy and stores the result as a new DRAFT
// version. It goes through validation, tests and the publish gate like any
// draft (HR-561).
func (s *Service) policyRoute(ctx context.Context, c tapp.Caller, it domain.Item, b domain.PolicyTemplateBody, params, details map[string]string) (draft, error) {
	spec := make(map[string]render.Spec, len(b.Placeholders))
	for k, v := range b.Placeholders {
		spec[k] = render.Spec{Kind: v.Kind, Pattern: v.Pattern}
	}
	rest := maps.Clone(params)
	if rest == nil {
		rest = map[string]string{}
	}
	env, agent := rest["environment"], rest["agent"]
	delete(rest, "environment")
	delete(rest, "agent")
	opts, err := packs.RenderOptions(it.Name, spec, rest)
	if err != nil {
		return draft{}, err
	}
	opts.Environment, opts.Agent = env, agent
	if _, ok := spec[render.KindEnvironmentID]; ok && env != "" {
		id, err := s.Store.EnvironmentID(ctx, c.Org, env)
		if err != nil {
			return draft{}, err
		}
		opts.EnvironmentID = id.String()
	}
	data, err := render.RenderItems(opts, spec, b.Rules, b.Tests)
	if err != nil {
		return draft{}, fmt.Errorf("%w: %w", domain.ErrItem, err)
	}
	// merged is the draft's bundle over the policy published now, with the
	// ids it changes and the version it expects to replace.
	merged := func(ctx context.Context) (raw []byte, replaced []string, expected ids.UUID, err error) {
		pub, err := s.Policies.Published(ctx)
		if err != nil {
			return nil, nil, expected, err
		}
		bundle := map[string]any{"id": "org-policy", "rules": []any{}}
		if pub != nil {
			if err := json.Unmarshal(pub.Bundle, &bundle); err != nil {
				return nil, nil, expected, err
			}
			expected = pub.ID
		}
		delete(bundle, "version")
		rules, errRules := merge(bundle, "rules", data.Rules)
		tests, errTests := merge(bundle, "tests", data.Tests)
		if err := errors.Join(errRules, errTests); err != nil {
			return nil, nil, expected, fmt.Errorf("%w: %w", domain.ErrItem, err)
		}
		raw, err = json.Marshal(bundle, json.Deterministic(true))
		return raw, append(rules, tests...), expected, err
	}
	return draft{
		create: func(ctx context.Context) (result, error) {
			raw, replaced, expected, err := merged(ctx)
			if err != nil {
				return result{}, err
			}
			v, err := s.Policies.CreateExpectingWith(ctx, raw, &expected, details)
			if err != nil {
				return result{}, err
			}
			return result{kind: ResultPolicyVersion, ref: v.ID.String(), skipped: data.Skipped, replaced: replaced}, nil
		},
		find: func(ctx context.Context) (result, bool, error) {
			raw, replaced, _, err := merged(ctx)
			if err != nil {
				return result{}, false, err
			}
			id, ok, err := s.Policies.FindDraft(ctx, raw)
			return result{kind: ResultPolicyVersion, ref: id, skipped: data.Skipped, replaced: replaced}, ok, err
		},
	}, nil
}

// merge adds items to the bundle's list, replacing those with the same id,
// and returns the ids whose content changed.
func merge(bundle map[string]any, key string, items []map[string]any) ([]string, error) {
	list, _ := bundle[key].([]any)
	var replaced []string
	for _, item := range items {
		i := slices.IndexFunc(list, func(x any) bool { m, _ := x.(map[string]any); return m["id"] == item["id"] })
		if i < 0 {
			list = append(list, item)
			continue
		}
		have, err := json.Marshal(list[i], json.Deterministic(true))
		if err != nil {
			return nil, err
		}
		want, err := json.Marshal(item, json.Deterministic(true))
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(have, want) {
			replaced = append(replaced, fmt.Sprint(item["id"]))
		}
		list[i] = item
	}
	if len(list) > maxBundleItems {
		return nil, fmt.Errorf("the draft would hold more than %d %s", maxBundleItems, key)
	}
	if len(list) > 0 || key == "rules" {
		bundle[key] = list
	}
	return replaced, nil
}
