// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/katocxl/pantherclaw/templates"
)

// pclaw template list and show (G0 M11.1 D16, F172–F178): read the
// templates shipped in templates/ and print each one's disclosure, what it
// protects, what it does not and what it needs, before anyone applies it.
// Both read only the embedded files; neither contacts the server.

func init() {
	commands["template list"] = command{usage: "template list", run: templateList}
	commands["template show"] = command{usage: "template show NAME", run: templateShow}
}

// templateInfo is a template's template.json.
type templateInfo struct {
	Name     string   `json:"name"`
	Summary  string   `json:"summary"`
	TaskRef  string   `json:"task_ref"`
	Protects []string `json:"protects"`
	Excludes []string `json:"excludes"`
	Requires struct {
		Packages    []string `json:"packages"`
		Connections []string `json:"connections"`
	} `json:"requires"`
	// Placeholders are the values the template's files use (D27).
	Placeholders map[string]placeholderSpec `json:"placeholders"`
	// Routes are the connection routes its rules decide; apply warns about
	// any in monitor mode.
	Routes []templateRoute `json:"routes"`
	// Grant says what the template's grant allows, for the plan.
	Grant string `json:"grant"`
	// RequiresAgent: the template is applied only with --agent (D114).
	RequiresAgent bool `json:"requires_agent,omitzero"`
	// RequiresScope: the template is applied only with --team or --bu, the
	// scope of the envelope that carries its weekly cap (D120).
	RequiresScope bool `json:"requires_scope,omitzero"`
}

// templateRoute is a connection route of a package.
type templateRoute struct {
	Package string `json:"package"`
	Route   string `json:"route"`
}

// templateNames lists the embedded templates, sorted.
func templateNames() ([]string, error) {
	entries, err := fs.ReadDir(templates.FS, ".")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	return names, nil
}

// readTemplateInfo reads a template's template.json.
func readTemplateInfo(name string) (templateInfo, error) {
	var info templateInfo
	if !templateNameRe.MatchString(name) {
		return info, fmt.Errorf("no template %q", name)
	}
	raw, err := fs.ReadFile(templates.FS, name+"/template.json")
	if errors.Is(err, fs.ErrNotExist) {
		return info, fmt.Errorf("no template %q (pclaw template list)", name)
	} else if err != nil {
		return info, err
	}
	if err := json.Unmarshal(raw, &info); err != nil {
		return info, fmt.Errorf("template %s/template.json: %w", name, err)
	}
	return info, nil
}

func templateList(_ context.Context, a *app, args []string) error {
	if len(args) != 0 {
		return errUsage
	}
	names, err := templateNames()
	if err != nil {
		return err
	}
	for _, n := range names {
		info, err := readTemplateInfo(n)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(a.stdout, "%-24s %s\n", n, info.Summary)
	}
	_, _ = fmt.Fprintln(a.stdout, "Show one's disclosure with pclaw template show NAME.")
	return nil
}

func templateShow(_ context.Context, a *app, args []string) error {
	if len(args) != 1 || strings.HasPrefix(args[0], "-") {
		return errUsage
	}
	info, err := readTemplateInfo(args[0])
	if err != nil {
		return err
	}
	w := a.stdout
	_, _ = fmt.Fprintf(w, "%s: %s\n", info.Name, info.Summary)
	list := func(title string, items []string) {
		_, _ = fmt.Fprintln(w, title)
		if len(items) == 0 {
			_, _ = fmt.Fprintln(w, "  (none)")
		}
		for _, it := range items {
			_, _ = fmt.Fprintf(w, "  - %s\n", it)
		}
	}
	list("Protects:", info.Protects)
	list("Does not protect:", info.Excludes)
	list("Requires packages:", info.Requires.Packages)
	list("Requires connections:", info.Requires.Connections)
	return nil
}
