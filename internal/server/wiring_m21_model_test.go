// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	modelapp "github.com/katocxl/pantherclaw/internal/model/app"
)

// notOfferedToModels are the shipped packages left out of builtinPackages on
// purpose, each with why. A new package is offered unless it is named here.
var notOfferedToModels = map[string]string{}

// TestModelIsToldOfEveryShippedPackage: each package under packages/ is
// offered to a model or left out by name (D329), so a new package cannot
// fail as MODEL_OUTPUT_INVALID with no sign why.
//
// Covers: F181
func TestModelIsToldOfEveryShippedPackage(t *testing.T) {
	root := filepath.Join("..", "..", "packages")
	dirs, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	pkgs, err := builtinPackages()
	if err != nil {
		t.Fatal(err)
	}
	offered := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		offered = append(offered, p.Name)
	}
	shipped := 0
	for _, d := range dirs {
		raw, err := os.ReadFile(filepath.Join(root, d.Name(), "package.yaml"))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		p, err := manifest.Decode(raw)
		if err != nil {
			t.Fatalf("%s: %v", d.Name(), err)
		}
		shipped++
		_, left := notOfferedToModels[p.Name]
		if in := slices.Contains(offered, p.Name); in == left {
			t.Errorf("%s: offered %v, left out %v: it must be exactly one of them", p.Name, in, left)
		}
	}
	if shipped < 12 {
		t.Fatalf("%d packages: the walk is not reading packages/", shipped)
	}
}

// TestModelIsOfferedM20sOperations: the operations a rule or guard on M20's
// packages names are offered (D329).
//
// Covers: F181
func TestModelIsOfferedM20sOperations(t *testing.T) {
	pkgs, err := builtinPackages()
	if err != nil {
		t.Fatal(err)
	}
	builtin := modelapp.BuiltinOperations(pkgs...)
	for _, op := range []string{"aws.ecs.service.deploy", "gitlab.merge_request.merge", "jira.issue.create", "teams.message.post"} {
		if !slices.Contains(builtin, op) {
			t.Errorf("%s is not offered", op)
		}
	}
}
