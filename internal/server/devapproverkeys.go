// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/katocxl/pantherclaw/internal/approvals/proof"
	"github.com/katocxl/pantherclaw/internal/authn/cose"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// approverKeysFile is the approver keys file dev seed writes next to a
// gateway's enrollment file, which deploy/dev/gateway.example.json pins.
func approverKeysFile(enrollFile string) string {
	return filepath.Join(filepath.Dir(enrollFile), "approver-keys.json")
}

// writeApproverKeys writes the org's approver keys file for a development
// gateway (HR-038): the active security keys of its people, as `pclaw
// approver-keys export` would. A new org has none, so its gateway refuses
// every approved action until someone adds a key and exports again. With
// security keys off (an IP-address public URL) nothing is written. It
// returns how many keys it wrote, and false when it wrote no file.
// DEVELOPMENT ONLY: in production a person exports and reviews the file.
func writeApproverKeys(ctx context.Context, cfg *Config, pool *db.Pool, org ids.OrgID, path string) (int, bool, error) {
	rp := cfg.webAuthnRPID()
	if rp == "" {
		return 0, false, nil
	}
	f := proof.File{Format: proof.FileFormat, Org: org.String(), RPID: rp, ExportedAt: time.Now().UTC().Truncate(time.Second)}
	err := pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ApproverKeys(ctx, org, ids.UUID{}, 10000)
		if err != nil {
			return err
		}
		for _, r := range rows {
			alg, der, err := cose.PKIX(r.PublicKey)
			if err != nil {
				return fmt.Errorf("dev: security key %s: %w", r.ID, err)
			}
			f.Keys = append(f.Keys, proof.NewFileKey(r.UserID.String(), r.Email, r.Name, r.CredentialID, alg, der))
		}
		return nil
	}, db.ReadOnly())
	if err != nil {
		return 0, false, err
	}
	b, err := f.Marshal()
	if err != nil {
		return 0, false, err
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return 0, false, fmt.Errorf("dev: approver keys file: %w", err)
	}
	return len(f.Keys), true, nil
}

// seedApproverKeys writes the approver keys file next to enrollFile and
// says what it did.
func seedApproverKeys(ctx context.Context, cfg *Config, pool *db.Pool, org ids.OrgID, enrollFile string, stdout io.Writer) error {
	path := approverKeysFile(enrollFile)
	n, wrote, err := writeApproverKeys(ctx, cfg, pool, org, path)
	switch {
	case err != nil:
		return err
	case !wrote:
		_, _ = fmt.Fprintln(stdout, "security keys are off (the public URL is an IP address), so the gateway refuses every approved action")
	default:
		_, _ = fmt.Fprintf(stdout, "wrote the approver keys file %s (%d keys); after people add security keys, refresh it with: "+
			"pclaw approver-keys export --out %s\n", path, n, path)
	}
	return nil
}
