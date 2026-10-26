// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
)

// pclaw verify (G0 M7 design decisions 13 and 15, HR-196, PN-007.4) checks
// a verify bundle, or an evidence pack and the bundles inside it, offline
// against a trust file the user pinned, and optionally a Sigstore trusted
// root and a checkpoint saved earlier. It makes no network
// call at all: it never uses the HTTP client and needs no login. It exits
// non-zero when any check failed.

const maxPreviousBytes = 64 << 10

func init() {
	commands["verify"] = command{
		usage: "verify [export|deletion] FILE --trust FILE [--parts DIR] [--sigstore-trusted-root FILE] [--previous FILE] [--json]",
		run:   verifyCmd,
	}
}

func verifyCmd(_ context.Context, a *app, args []string) error {
	kind := "evidence"
	if len(args) > 0 && (args[0] == "export" || args[0] == "deletion") {
		kind, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	trustFile := fs.String("trust", "", "trust file (pantherclaw.trust/v1) with the evidence keys you pinned")
	sigstoreFile := fs.String("sigstore-trusted-root", "", "Sigstore trusted_root.json, to check anchors in a transparency log and their timestamps")
	previousFile := fs.String("previous", "", "a checkpoint you saved earlier, to check the bundle's history extends it")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	partsDir := fs.String("parts", "", "export parts directory, containing part-001.zip, part-002.zip, ...")
	var positional []string
	for rest := args; ; {
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if fs.NArg() == 0 {
			break
		}
		positional = append(positional, fs.Arg(0))
		rest = fs.Args()[1:]
	}
	if len(positional) != 1 || *trustFile == "" || (*partsDir != "" && kind != "export") {
		return errUsage
	}

	opts := bundle.Options{}
	raw, err := readLimited(*trustFile, bundle.MaxTrustBytes)
	if err != nil {
		return err
	}
	if opts.Trust, err = bundle.ParseTrust(raw); err != nil {
		return err
	}
	if *sigstoreFile != "" {
		if raw, err = readLimited(*sigstoreFile, bundle.MaxSigstoreRootBytes); err != nil {
			return err
		}
		if opts.Sigstore, err = bundle.ParseSigstoreRoot(raw); err != nil {
			return err
		}
	}
	if *previousFile != "" {
		if opts.Previous, err = readLimited(*previousFile, maxPreviousBytes); err != nil {
			return err
		}
	}
	limit := int64(bundle.MaxBundleBytes)
	if kind != "evidence" {
		limit = bundle.MaxDataDocumentBytes
	}
	raw, err = readLimited(positional[0], limit)
	if err != nil {
		return err
	}
	var report *bundle.Report
	if kind == "export" {
		if *partsDir == "" {
			*partsDir = filepath.Dir(positional[0])
		}
		parts, openErr := os.OpenRoot(*partsDir)
		if openErr != nil {
			return openErr
		}
		report = bundle.VerifyExport(raw, parts.FS(), opts)
		if err := parts.Close(); err != nil {
			return err
		}
	} else if kind == "deletion" {
		report = bundle.VerifyDeletion(raw, opts)
	} else if bundle.IsPack(raw) {
		// An evidence pack (a ZIP with a signed manifest, HR-196): its
		// manifest, every file and the verify bundles inside.
		report = bundle.VerifyPack(raw, opts)
	} else if b, err := bundle.Decode(raw); err != nil {
		report = bundle.Invalid(err)
	} else {
		report = bundle.Verify(b, opts)
	}

	if *asJSON {
		out, err := report.JSON()
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintln(a.stdout, string(out))
	} else {
		_, _ = fmt.Fprint(a.stdout, report.Text())
	}
	if report.Failed() {
		return &exitError{code: 1, msg: fmt.Sprintf("pclaw: verification failed (%d checks failed)", report.Count(bundle.Failed))}
	}
	return nil
}

// readLimited reads a file of at most limit bytes.
func readLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the user names the file
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	if len(b) == 0 {
		return nil, errors.New(path + " is empty")
	}
	return b, nil
}
