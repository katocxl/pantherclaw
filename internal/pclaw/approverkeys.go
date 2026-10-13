// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/katocxl/pantherclaw/internal/approvals/proof"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// The approver keys file (G0 M6 slice 23, HR-038): a customer-hosted
// gateway verifies every approval a permit carries against the security
// keys in a file its operator installed. `approver-keys export` writes that
// file from the org's active keys and prints each key's fingerprint, so a
// person reviews who can approve before the gateway trusts it.

func init() {
	commands["approver-keys export"] = command{usage: "approver-keys export --out FILE", run: exportApproverKeys}
}

var algorithmNames = map[int32]string{proof.AlgES256: "ES256", proof.AlgEdDSA: "EdDSA", proof.AlgRS256: "RS256"}

func exportApproverKeys(ctx context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("approver-keys export", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	out := fs.String("out", "", "write the approver keys file here (replaced if it exists)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *out == "" {
		return errUsage
	}
	c, err := a.clients()
	if err != nil {
		return err
	}
	f := proof.File{Format: proof.FileFormat, ExportedAt: time.Now().UTC().Truncate(time.Second), Keys: []proof.FileKey{}}
	token := ""
	for {
		res, err := c.gateways.ListApproverKeys(ctx, &pb.ListApproverKeysRequest{PageSize: 200, PageToken: token})
		if err != nil {
			return err
		}
		if f.Org == "" {
			f.Org, f.RPID = res.GetOrgId(), res.GetRpId()
		} else if f.Org != res.GetOrgId() || f.RPID != res.GetRpId() {
			return errors.New("the server changed org or relying party between pages; nothing was written")
		}
		for _, k := range res.GetKeys() {
			fk := proof.NewFileKey(k.GetUserId(), label(k), k.GetName(), k.GetCredentialId(), int(k.GetAlgorithm()), k.GetPublicKey())
			if fk.Fingerprint != k.GetFingerprint() {
				return fmt.Errorf("key %s does not match its fingerprint; nothing was written", k.GetId())
			}
			f.Keys = append(f.Keys, fk)
		}
		if token = res.GetNextPageToken(); token == "" {
			break
		}
	}
	b, err := f.Marshal()
	if err != nil {
		return err
	}
	// Write only what a gateway will load.
	if _, err := proof.ParseFile(b); err != nil {
		return fmt.Errorf("the export does not form a valid file; nothing was written: %w", err)
	}
	if err := replaceFile(*out, b); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(a.stdout, "Approver keys of org %s for relying party %s: %d key(s)\n", f.Org, f.RPID, len(f.Keys))
	for _, k := range proof.Sorted(f.Keys) {
		_, _ = fmt.Fprintf(a.stdout, "  %q  key %q  %s  %s\n", k.Label, k.KeyName, algorithmNames[int32(k.Algorithm)], k.Fingerprint) //nolint:gosec // a COSE id
	}
	_, _ = fmt.Fprintf(a.stdout, "Wrote %s. Review every person and fingerprint before the gateway's operator installs it as "+
		"approvals.approver_keys_file: the gateway dispatches an approved action only when every approver's key is in it.\n", *out)
	return nil
}

// label names a key's person for review: email and display name, both
// untrusted text from the identity provider.
func label(k *pb.ApproverKey) string {
	switch {
	case k.GetUserDisplayName() != "" && k.GetUserEmail() != "":
		return k.GetUserEmail() + " (" + k.GetUserDisplayName() + ")"
	case k.GetUserEmail() != "":
		return k.GetUserEmail()
	case k.GetUserDisplayName() != "":
		return k.GetUserDisplayName()
	}
	return "user " + k.GetUserId()
}

// replaceFile writes b to path through a temporary file in the same
// directory, so a gateway reading it never sees half a file.
func replaceFile(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".approver-keys-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
