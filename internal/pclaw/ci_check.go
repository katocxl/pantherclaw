// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/katocxl/pantherclaw/internal/policy/offline"
)

// pclaw ci check (G0 M23 D121): a policy file through the publish gate's
// validator, scenarios and mutants, and its rule diff from a base, with no
// server and no network. Exit 0 passed, 1 the check failed, 2 it could not
// run on what it was given.

func init() {
	commands["ci check"] = command{
		usage: "ci check --policy F [--base F] [--scenarios DIR] [--packages DIR] [--format text|json|markdown] [--fail-on widen|any]",
		run:   ciCheck,
	}
}

func ciCheck(ctx context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("ci check", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	var o offline.Options
	var failOn string
	fs.StringVar(&o.PolicyFile, "policy", "", "the policy bundle to check (JSON, as pclaw policy create takes it)")
	fs.StringVar(&o.BaseFile, "base", "", "the bundle it replaces: rule changes and outcome samples compare with it")
	fs.StringVar(&o.ScenariosDir, "scenarios", "", "directory of scenario fixtures (.json), added to the bundle's own tests")
	fs.StringVar(&o.PackagesDir, "packages", "", "directory of package.yaml files, with an optional facts.json (default: the packages built into pclaw)")
	format := fs.String("format", "text", "text, json or markdown")
	fs.StringVar(&failOn, "fail-on", string(offline.FailWiden), "widen fails on a change not provably tighter; any on every rule change")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return errUsage
	}
	if fs.NArg() != 0 || o.PolicyFile == "" || (failOn != string(offline.FailWiden) && failOn != string(offline.FailAny)) {
		return errUsage
	}
	if *format != "text" && *format != "json" && *format != "markdown" {
		return errUsage
	}
	o.FailOn = offline.FailOn(failOn)
	r, err := offline.Check(ctx, o)
	if err != nil {
		return &exitError{code: 2, msg: "pclaw ci check: " + offline.Plain(err.Error())}
	}
	var out []byte
	switch *format {
	case "json":
		if out, err = r.JSON(); err != nil {
			return &exitError{code: 2, msg: "pclaw ci check: " + offline.Plain(err.Error())}
		}
	case "markdown":
		out = r.Markdown()
	default:
		out = r.Text()
	}
	if _, err := a.stdout.Write(out); err != nil {
		return &exitError{code: 2, msg: "pclaw ci check: " + offline.Plain(err.Error())}
	}
	if !r.Passed {
		return &exitError{code: 1, msg: fmt.Sprintf("pclaw ci check: failed (%d)", len(r.Failures))}
	}
	return nil
}
