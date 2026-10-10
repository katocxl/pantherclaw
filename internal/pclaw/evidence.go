// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/katocxl/pantherclaw/internal/evidence/bundle"
	"github.com/katocxl/pantherclaw/internal/evidence/keydocs"
	"github.com/katocxl/pantherclaw/internal/evidence/note"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// pclaw evidence trust|bundle (G0 M7 design decision 13, HR-196).
//
// `evidence trust` fetches the deployment's evidence-keys.json once (trust
// on first use), prints every key's fingerprint for comparison through
// another channel, and writes the trust file `pclaw verify` uses.
// `evidence bundle` asks the deployment for a verify bundle and writes it;
// `pclaw verify` then checks it offline.

func init() {
	commands["evidence trust"] = command{
		usage: "evidence trust --out FILE [--server URL]",
		run:   evidenceTrust,
	}
	commands["evidence bundle"] = command{
		usage: "evidence bundle (--txn ID [--txn ID]… | --from SEQ --to SEQ) [--previous FILE] --out FILE",
		run:   evidenceBundle,
	}
}

// writeNew writes b to a file that must not exist yet.
func writeNew(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: the user names the file
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// evidenceServer is the deployment to fetch from: --server, or the
// signed-in session's (PANTHERCLAW_SERVER or the stored login).
func (a *app) evidenceServer(flagged string) (string, error) {
	if flagged != "" {
		return checkServer(flagged)
	}
	s, err := a.session()
	if err != nil {
		return "", errors.New("give --server, or sign in first (pclaw login)")
	}
	return s.server, nil
}

// fingerprint is the SHA-256 of a key's published public key, in hex.
func fingerprint(public []byte) string {
	sum := sha256.Sum256(public)
	return "SHA256:" + hex.EncodeToString(sum[:])
}

func evidenceTrust(ctx context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("evidence trust", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	out := fs.String("out", "", "trust file to write (must not exist)")
	server := fs.String("server", "", "deployment base URL (default: the signed-in server)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" || fs.NArg() != 0 {
		return errUsage
	}
	base, err := a.evidenceServer(*server)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+keydocs.EvidenceKeysPath, nil)
	if err != nil {
		return err
	}
	resp, err := a.http.Do(req)
	if err != nil {
		return fmt.Errorf("fetching evidence keys: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetching evidence keys: %s answered %d", base, resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, bundle.MaxTrustBytes+1))
	if err != nil {
		return err
	}
	trust, err := bundle.ParseEvidenceKeys(raw)
	if err != nil {
		return err
	}
	if trust.Issuer != "" && trust.Issuer != base {
		_, _ = fmt.Fprintf(a.stderr, "warning: the document names its issuer %s, but it came from %s\n", trust.Issuer, base)
	}
	doc, err := json.Marshal(trust, json.Deterministic(true))
	if err != nil {
		return err
	}
	if err := writeNew(*out, doc); err != nil {
		return err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Pinned %d evidence keys of %s (log origin %s) in %s:\n", len(trust.Keys), base, trust.LogOrigin, *out)
	for _, k := range trust.Keys {
		fmt.Fprintf(&b, "  %-40s %-15s %-10s %-9s %s\n", k.KID, k.Purpose, k.Algorithm, k.State, fingerprint(k.PublicKey))
	}
	b.WriteString("Compare these fingerprints with the deployment's operator through another channel before you rely on " +
		"this trust file. pclaw verify trusts these keys and nothing else.\n")
	_, err = fmt.Fprint(a.stdout, b.String())
	return err
}

// savedCheckpointSize returns the tree size of a checkpoint note saved
// earlier; pclaw verify --previous checks its signature.
func savedCheckpointSize(path string) (uint64, error) {
	raw, err := readLimited(path, maxPreviousBytes)
	if err != nil {
		return 0, err
	}
	n, err := note.Parse(raw)
	if err != nil {
		return 0, fmt.Errorf("%s is not a signed checkpoint: %w", path, err)
	}
	c, err := note.ParseCheckpoint(n.Text)
	if err != nil {
		return 0, fmt.Errorf("%s is not a signed checkpoint: %w", path, err)
	}
	return c.Size, nil
}

func evidenceBundle(ctx context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("evidence bundle", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	var txns list
	fs.Var(&txns, "txn", "a transaction to include (repeat, at most 50)")
	from := fs.Int64("from", 0, "first ledger sequence number of a range")
	to := fs.Int64("to", 0, "last ledger sequence number of a range (at most 1,000 entries)")
	previous := fs.String("previous", "", "a checkpoint you saved earlier: the bundle also proves its history extends it")
	out := fs.String("out", "", "bundle file to write (must not exist)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	byRange := *from != 0 || *to != 0
	if *out == "" || fs.NArg() != 0 || (len(txns) == 0) == !byRange {
		return errUsage
	}
	req := &pantherclawv1.ExportBundleRequest{}
	if byRange {
		req.Selection = &pantherclawv1.ExportBundleRequest_Range{Range: &pantherclawv1.BundleRange{FromSeq: *from, ToSeq: *to}}
	} else {
		req.Selection = &pantherclawv1.ExportBundleRequest_Transactions{Transactions: &pantherclawv1.BundleTransactions{Ids: txns}}
	}
	if *previous != "" {
		size, err := savedCheckpointSize(*previous)
		if err != nil {
			return err
		}
		req.ConsistencyFrom = size
	}
	s, err := a.session()
	if err != nil {
		return err
	}
	res, err := pantherclawv1connect.NewEvidenceServiceClient(s.connect()).ExportBundle(ctx, req)
	if err != nil {
		return err
	}
	if _, err := bundle.Decode(res.GetBundle()); err != nil {
		return fmt.Errorf("the server sent an invalid bundle: %w", err)
	}
	if err := writeNew(*out, res.GetBundle()); err != nil {
		return err
	}
	cp := "no checkpoint yet"
	if res.GetCheckpointSize() > 0 {
		cp = fmt.Sprintf("checkpoint of size %d", res.GetCheckpointSize())
	}
	_, err = fmt.Fprintf(a.stdout, "Wrote %d ledger entries and %d receipts (%s) to %s. Check it with: pclaw verify %s --trust FILE\n",
		res.GetEntries(), res.GetReceipts(), cp, *out, *out)
	return err
}
