// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/definitions/openapi"
)

// pclaw package draft openapi (G0 M31 D953, HR-720) drafts an unsigned tool
// package from an OpenAPI 3 spec on this machine. Nothing is sent to the
// server: the draft starts with review_required, which no package decoder
// accepts, so it can only be imported after a person reviews it, removes
// the key and signs it with an org package key.
func init() {
	commands["package draft openapi"] = command{
		usage: "package draft openapi SPEC.json|SPEC.yaml --name ORG.NAME --version X.Y.Z --out FILE [--operations ID1,ID2]",
		run:   packageDraftOpenAPI,
	}
}

func packageDraftOpenAPI(_ context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("package draft openapi", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	name := fs.String("name", "", "the package name, your organization's prefix first (never pc.)")
	version := fs.String("version", "", "the package version, MAJOR.MINOR.PATCH")
	out := fs.String("out", "", "write the draft to this file")
	ops := fs.String("operations", "", "draft only these operation ids, comma separated (default: every operation)")
	// The spec comes first; flags may follow it.
	var spec string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		spec, args = args[0], args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if spec == "" && fs.NArg() == 1 {
		spec = fs.Arg(0)
	} else if fs.NArg() != 0 {
		return errUsage
	}
	if spec == "" || *name == "" || *version == "" || *out == "" {
		return errUsage
	}
	raw, err := readSpec(spec)
	if err != nil {
		return err
	}
	s, err := openapi.Parse(raw)
	if err != nil {
		return err
	}
	var only []string
	for _, id := range strings.Split(*ops, ",") {
		if id = strings.TrimSpace(id); id != "" {
			only = append(only, id)
		}
	}
	draft, err := openapi.Draft(s, openapi.DraftOptions{Name: *name, Version: *version, Operations: only, Source: spec, Now: time.Now()})
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, draft, 0o600); err != nil {
		return err
	}
	_, err = fmt.Fprintf(a.stderr, "Wrote an UNSIGNED draft of %s %s to %s.\n"+
		"It does not load until a person reviews every review_required item and \"# review:\" comment, removes review_required,\n"+
		"and signs it with an org package key (pclaw package sign).\n", *name, *version, *out)
	if err == nil && s.Server != "" {
		_, err = fmt.Fprintf(a.stderr, "The spec's first server is %s: a hint for the connection's base URL.\n", escapeControls(s.Server))
	}
	return err
}

// readSpec reads a spec file of at most openapi.MaxSpecBytes.
func readSpec(path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the operator names the file
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, openapi.MaxSpecBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > openapi.MaxSpecBytes {
		return nil, fmt.Errorf("the spec is larger than %d bytes", openapi.MaxSpecBytes)
	}
	return b, nil
}
