// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package offline

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"strings"

	"github.com/katocxl/pantherclaw/internal/automations/assurance"
	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	"github.com/katocxl/pantherclaw/internal/policy/scenario"
	mockpayments "github.com/katocxl/pantherclaw/packages/mock-payments"
	pca2a "github.com/katocxl/pantherclaw/packages/pc-a2a"
	pcaws "github.com/katocxl/pantherclaw/packages/pc-aws"
	pcawsecs "github.com/katocxl/pantherclaw/packages/pc-aws-ecs"
	pcgithub "github.com/katocxl/pantherclaw/packages/pc-github"
	pcgitlab "github.com/katocxl/pantherclaw/packages/pc-gitlab"
	pcjira "github.com/katocxl/pantherclaw/packages/pc-jira"
	pcpostgres "github.com/katocxl/pantherclaw/packages/pc-postgres"
	pcshell "github.com/katocxl/pantherclaw/packages/pc-shell"
	pcslack "github.com/katocxl/pantherclaw/packages/pc-slack"
	pcstripe "github.com/katocxl/pantherclaw/packages/pc-stripe"
	pcteams "github.com/katocxl/pantherclaw/packages/pc-teams"
)

// Bounds of what one check reads. A check runs on a pull request's own
// files, so nothing in them may make it read without end.
const (
	maxFileBytes  = 4 << 20
	maxDirEntries = 5000
	// maxAutomations bounds the automation scenario files of one check: each
	// runs up to assurance.MaxCases simulations.
	maxAutomations = 20
)

// FactsFile is the file in --packages that declares the facts rules read.
const FactsFile = "facts.json"

// world is the file-based definitions and facts source. It implements the
// read ports of the scenario runner and the validator.
type world struct {
	defs     []*defs.Definition
	pkgs     []*defs.Package
	facts    map[string]fdomain.Type
	subjects map[string]string
}

// ActiveDefinitions implements scenario.Definitions and validate.Definitions.
func (w *world) ActiveDefinitions(context.Context, ids.OrgID) ([]*defs.Definition, error) {
	return w.defs, nil
}

// ActivePackages implements scenario.Packages.
func (w *world) ActivePackages(context.Context, ids.OrgID) ([]*defs.Package, error) {
	return w.pkgs, nil
}

// Catalog implements scenario.Catalog and validate.Catalog.
func (w *world) Catalog(context.Context, ids.OrgID) (map[string]fdomain.Type, error) {
	return maps.Clone(w.facts), nil
}

// FactSubjects implements validate.Subjects.
func (w *world) FactSubjects(context.Context, ids.OrgID) (map[string]string, error) {
	return maps.Clone(w.subjects), nil
}

func (w *world) add(p *defs.Package) {
	w.pkgs = append(w.pkgs, p)
	for i := range p.Definitions {
		w.defs = append(w.defs, &p.Definitions[i])
	}
}

// builtin are the packages this build ships, the definitions of a check
// that names no --packages.
func builtin() [][]byte {
	return [][]byte{
		mockpayments.Package, pca2a.Package, pcaws.Package, pcawsecs.Package, pcgithub.Package, pcgitlab.Package, pcjira.Package,
		pcpostgres.Package, pcshell.Package, pcslack.Package, pcstripe.Package, pcteams.Package,
	}
}

// loadWorld reads dir, or takes the built-in packages when dir is empty.
// A directory replaces them: the same operation in two packages could not
// tell a case which definition decides.
func loadWorld(dir string) (*world, error) {
	w := &world{facts: map[string]fdomain.Type{}, subjects: map[string]string{}}
	if dir == "" {
		for _, raw := range builtin() {
			p, err := manifest.Decode(raw)
			if err != nil {
				return nil, fmt.Errorf("offline: built-in package: %w", err)
			}
			w.add(p)
		}
		return w, nil
	}
	err := walk(dir, func(path string) error {
		name := filepath.Base(path)
		if !isManifest(name) {
			if name == FactsFile && filepath.Dir(path) == filepath.Clean(dir) {
				return w.loadFacts(path)
			}
			return nil
		}
		raw, err := readBounded(path)
		if err != nil {
			return err
		}
		p, err := manifest.Decode(raw)
		if err != nil {
			return inputf("%s: %v", path, err)
		}
		w.add(p)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(w.pkgs) == 0 {
		return nil, inputf("--packages %s holds no package.yaml", dir)
	}
	return w, nil
}

// isManifest: package.yaml, or NAME.package.yaml.
func isManifest(name string) bool {
	return name == "package.yaml" || strings.HasSuffix(name, ".package.yaml")
}

// factsDoc is facts.json.
type factsDoc struct {
	Facts []factDecl `json:"facts"`
}

type factDecl struct {
	Name        string       `json:"name"`
	Type        fdomain.Type `json:"type"`
	SubjectType string       `json:"subject_type,omitzero"`
}

func (w *world) loadFacts(path string) error {
	raw, err := readBounded(path)
	if err != nil {
		return err
	}
	var doc factsDoc
	if err := json.Unmarshal(raw, &doc, json.RejectUnknownMembers(true)); err != nil {
		return inputf("%s: %v", path, err)
	}
	for _, f := range doc.Facts {
		switch f.Type {
		case fdomain.TypeBoolean, fdomain.TypeInteger, fdomain.TypeDecimal, fdomain.TypeMoney, fdomain.TypeIdentifier, fdomain.TypeTimestamp, fdomain.TypeObject:
		default:
			return inputf("%s: fact %q has no known type", path, f.Name)
		}
		if f.Name == "" {
			return inputf("%s: a fact has no name", path)
		}
		if _, dup := w.facts[f.Name]; dup {
			return inputf("%s: fact %s is declared twice", path, f.Name)
		}
		w.facts[f.Name] = f.Type
		if f.SubjectType != "" {
			w.subjects[f.Name] = f.SubjectType
		}
	}
	return nil
}

// inferFacts declares each fact the cases give and no file declares, by
// the type its value's wire form names ({"bool": true}). A value of no
// such form is left for its case to fail on.
func (w *world) inferFacts(cases []pdomain.TestCase) error {
	inferred := map[string]fdomain.Type{}
	for i := range cases {
		g := cases[i].Given
		if g == nil {
			continue
		}
		for name, f := range g.Facts {
			if _, declared := w.facts[name]; declared {
				continue
			}
			t := scenario.WireType(f.Value)
			if t == "" {
				continue
			}
			if other, ok := inferred[name]; ok && other != t {
				return inputf("the scenarios give fact %s as both %s and %s: declare it in %s", name, other, t, FactsFile)
			}
			inferred[name] = t
		}
	}
	maps.Copy(w.facts, inferred)
	return nil
}

// fixtures are the scenario fixtures of one directory.
type fixtures struct {
	tests       []pdomain.TestCase
	automations []automationFixture
}

type automationFixture struct {
	name  string
	def   *autodomain.Definition
	cases []assurance.Case
}

// scenarioDoc is one scenario file: policy cases, or an automation
// definition with its cases.
type scenarioDoc struct {
	Tests      []pdomain.TestCase `json:"tests,omitzero"`
	Automation jsontext.Value     `json:"automation,omitzero"`
	Cases      []assurance.Case   `json:"cases,omitzero"`
}

// loadScenarios reads every .json file under dir.
func loadScenarios(dir string) (fixtures, error) {
	var out fixtures
	if dir == "" {
		return out, nil
	}
	err := walk(dir, func(path string) error {
		if filepath.Ext(path) != ".json" {
			return nil
		}
		raw, err := readBounded(path)
		if err != nil {
			return err
		}
		var doc scenarioDoc
		if err := json.Unmarshal(raw, &doc, json.RejectUnknownMembers(true)); err != nil {
			return inputf("%s: %v", path, err)
		}
		switch {
		case len(doc.Tests) > 0 && len(doc.Automation) == 0 && len(doc.Cases) == 0:
			out.tests = append(out.tests, doc.Tests...)
		case len(doc.Tests) == 0 && len(doc.Automation) > 0:
			if len(out.automations) == maxAutomations {
				return inputf("--scenarios %s: more than %d automation scenario files", dir, maxAutomations)
			}
			def, err := autodomain.Parse(doc.Automation)
			if err != nil {
				return inputf("%s: %v", path, err)
			}
			if err := assurance.Check(def, doc.Cases); err != nil {
				return inputf("%s: %v", path, err)
			}
			rel, err := filepath.Rel(dir, path)
			if err != nil {
				rel = filepath.Base(path)
			}
			out.automations = append(out.automations, automationFixture{name: filepath.ToSlash(rel), def: def, cases: doc.Cases})
		default:
			return inputf(`%s: a scenario file holds {"tests": [...]} or {"automation": {...}, "cases": [...]}`, path)
		}
		return nil
	})
	return out, err
}

// walk calls fn on every regular file under dir, in lexical order. Links
// are not followed: a pull request's files stay what the check reads.
func walk(dir string, fn func(path string) error) error {
	info, err := os.Stat(dir)
	if err != nil {
		return inputf("%v", err)
	}
	if !info.IsDir() {
		return inputf("%s is not a directory", dir)
	}
	n := 0
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return inputf("%v", err)
		}
		if n++; n > maxDirEntries {
			return inputf("%s holds more than %d entries", dir, maxDirEntries)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		return fn(path)
	})
}

// readBounded reads a regular file of at most maxFileBytes. A link is
// refused, so that a file a pull request adds cannot point the check at
// something else on the runner.
func readBounded(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, inputf("%v", err)
	}
	if !info.Mode().IsRegular() {
		return nil, inputf("%s is not a regular file", path)
	}
	f, err := os.Open(path) //nolint:gosec // G304: a file the caller names
	if err != nil {
		return nil, inputf("%v", err)
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return nil, inputf("%s: %v", path, err)
	}
	if len(raw) > maxFileBytes {
		return nil, inputf("%s is larger than %d bytes", path, maxFileBytes)
	}
	return raw, nil
}

// ErrInput marks a check that could not run on what it was given (exit 2):
// a file that cannot be read, or an argument that means nothing.
var ErrInput = errors.New("offline: input")

func inputf(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInput}, args...)...)
}
