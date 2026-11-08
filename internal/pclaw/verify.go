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
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/evidence/sigstoretuf"
	"github.com/katocxl/pantherclaw/internal/evidence/witness"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
)

// pclaw verify (G0 M7 design decisions 13 and 15, HR-196, PN-007.4) checks
// a verify bundle, or an evidence pack and the bundles inside it, offline
// against a trust file the user pinned, and optionally a Sigstore trusted
// root and a checkpoint saved earlier. It makes no network call and needs
// no login, except with --sigstore-tuf, which fetches Sigstore's
// trusted_root.json through TUF from Sigstore's repository only (G0 M35
// D1040); --sigstore-trusted-root FILE keeps it offline. --witnesses names
// the witnesses whose cosignatures on the deployment-wide root log count
// (G0 M35 D1041). It exits non-zero when any check failed.

const (
	maxPreviousBytes  = 64 << 10
	maxWitnessesBytes = 64 << 10
	maxWitnesses      = 64
)

func init() {
	commands["verify"] = command{
		usage: "verify [export|deletion] FILE --trust FILE [--parts DIR] [--sigstore-trusted-root FILE | --sigstore-tuf [--tuf-cache DIR]] " +
			"[--witnesses FILE [--witness-threshold N]] [--previous FILE] [--json]",
		run: verifyCmd,
	}
}

func verifyCmd(ctx context.Context, a *app, args []string) error {
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
	useTUF := fs.Bool("sigstore-tuf", false, "fetch Sigstore's trusted_root.json through TUF from "+sigstoretuf.DefaultRepository)
	tufCache := fs.String("tuf-cache", "", "directory that keeps the verified TUF metadata between runs (with --sigstore-tuf)")
	witnessesFile := fs.String("witnesses", "", "file of witness verifier keys (cosignature/v1 vkeys, one per line) whose cosignatures count")
	witnessThreshold := fs.Int("witness-threshold", 1, "how many of the witnesses must have cosigned the root log's checkpoint")
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
	if len(positional) != 1 || *trustFile == "" || (*partsDir != "" && kind != "export") ||
		(*useTUF && *sigstoreFile != "") || (*tufCache != "" && !*useTUF) || *witnessThreshold < 1 {
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
	if *useTUF {
		// G0 M35 D1040: TUF-verified trust material, through the egress
		// client to Sigstore's repository only.
		c := &sigstoretuf.Client{CacheDir: *tufCache, HTTP: httpx.NewEgressClient(httpx.EgressConfig{Timeout: 30 * time.Second})}
		m, err := c.Fetch(ctx)
		if err != nil {
			return fmt.Errorf("pclaw: Sigstore TUF: %w", err)
		}
		if opts.Sigstore, err = bundle.ParseSigstoreRoot(m.TrustedRoot); err != nil {
			return err
		}
	}
	if *witnessesFile != "" {
		if raw, err = readLimited(*witnessesFile, maxWitnessesBytes); err != nil {
			return err
		}
		if opts.Witnesses, err = parseWitnesses(raw); err != nil {
			return err
		}
		if *witnessThreshold > len(opts.Witnesses) {
			return fmt.Errorf("pclaw: --witness-threshold %d is more than the %d witnesses in %s", *witnessThreshold, len(opts.Witnesses), *witnessesFile)
		}
		opts.WitnessThreshold = *witnessThreshold
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

// parseWitnesses reads witness verifier keys: one cosignature/v1 vkey per
// line; empty lines and lines starting with # are ignored.
func parseWitnesses(raw []byte) ([]*witness.Verifier, error) {
	var out []*witness.Verifier
	for i, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		v, err := witness.ParseVKey(line)
		if err != nil {
			return nil, fmt.Errorf("pclaw: witnesses line %d: %w", i+1, err)
		}
		out = append(out, v)
	}
	if len(out) == 0 || len(out) > maxWitnesses {
		return nil, fmt.Errorf("pclaw: the witnesses file needs 1..%d keys", maxWitnesses)
	}
	return out, nil
}
