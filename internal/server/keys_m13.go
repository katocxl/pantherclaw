// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"

	"github.com/jackc/pgx/v5"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// Operator key commands of G0 M13: signing-key rotation (D5, HR-372) and
// the post-restore epoch bump (D6, HR-373).

// operatorFlags parses --config and --confirm (and --all when all is not
// nil) for an operator command that takes no arguments.
func operatorFlags(name string, args []string, stderr io.Writer, all *bool) (cfgPath string, confirm bool, err error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("config", "", "JSON configuration file")
	ok := fs.Bool("confirm", false, "make the change")
	if all != nil {
		fs.BoolVar(all, "all", false, "every organization")
	}
	if err := fs.Parse(args); err != nil {
		return "", false, err
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return "", false, errUsage
	}
	return *path, *ok, nil
}

// openOperatorPool opens the app-role pool an operator command uses.
func openOperatorPool(ctx context.Context, cfgPath string, stderr io.Writer, env Env, name string) (*Config, *db.Pool, error) {
	cfg, _, err := loadConfig([]string{"--config", cfgPath}, stderr, env, name)
	if err != nil {
		return nil, nil, err
	}
	appCfg, err := cfg.dbConfig(cfg.DB.AppUser, cfg.DB.AppPasswordFile, 2)
	if err != nil {
		return nil, nil, err
	}
	pool, err := db.Open(ctx, appCfg)
	if err != nil {
		return nil, nil, err
	}
	return cfg, pool, nil
}

// rotation names the key sets one rotate command rotates.
type rotation struct {
	name string
	// purposes returns the purposes to rotate; optional ones are rotated
	// only when they have an active key.
	purposes, optional []keys.Purpose
}

var (
	rotateReceipts = rotation{name: "keys rotate-receipts", purposes: []keys.Purpose{keys.PurposeReceipts}}
	// The anchored global root is its own ceremony (HR-195), never rotated
	// here.
	rotateEvidence = rotation{
		name:     "keys rotate-evidence",
		purposes: []keys.Purpose{keys.PurposeCheckpoints, keys.PurposeEvidencePacks},
		optional: []keys.Purpose{keys.PurposeCheckpointsPQ},
	}
)

// cmdRotateSigning implements `keys rotate-receipts --confirm` and `keys
// rotate-evidence --confirm` (G0 M13 D5, HR-372): each purpose gets a new
// active key, and its previous key becomes RETIRING from now on: it no
// longer signs, but stays published in the well-known documents and
// verifies everything it signed. Audited with the operator as the actor.
// Without --confirm nothing changes.
func cmdRotateSigning(ctx context.Context, r rotation, args []string, stdout, stderr io.Writer, env Env) error {
	cfgPath, confirm, err := operatorFlags(r.name, args, stderr, nil)
	if err != nil {
		return err
	}
	if !confirm {
		return fmt.Errorf("%s: gives the keys a new signing key; earlier keys keep verifying; run again with --confirm", r.name)
	}
	cfg, pool, err := openOperatorPool(ctx, cfgPath, stderr, env, r.name)
	if err != nil {
		return err
	}
	defer pool.Close()
	kp, err := keys.NewFileProvider(cfg.KEKFiles)
	if err != nil {
		return err
	}
	purposes := append([]keys.Purpose(nil), r.purposes...)
	if len(r.optional) > 0 {
		published, err := keystore.PublishedKeys(ctx, pool, r.optional)
		if err != nil {
			return err
		}
		for _, p := range r.optional {
			for _, k := range published {
				if k.Purpose == p && k.State == keys.StateActive {
					purposes = append(purposes, p)
					break
				}
			}
		}
	}
	actor := evdomain.Actor{Type: "operator", ID: operatorName()}
	// Every purpose rotates in one transaction: all or none.
	kids, err := keystore.RotateSigningKeys(ctx, pool, kp, purposes, actor)
	if err != nil {
		return fmt.Errorf("%s: nothing rotated: %w", r.name, err)
	}
	for i, p := range purposes {
		_, _ = fmt.Fprintf(stdout, "rotated %s: new key %s; the previous key is retiring and keeps verifying\n", p, kids[i])
	}
	_, _ = fmt.Fprintln(stdout, "next: restart every server instance so it signs with the new keys (docs/runbooks/key-rotation.md)")
	return nil
}

// epochPageSize is how many orgs one lister page of an epoch bump lists;
// the bump pages through every org (D45). Tests lower it.
var epochPageSize = db.ListerPageSize

// cmdBumpEpochs implements `keys bump-epochs --all --confirm` (G0 M13 D6,
// HR-373), run after a database restore and before gateways reconnect:
// Every non-DELETED org gets the containment epoch max(epoch + 1,
// the database clock in Unix milliseconds) in its own transaction with the
// audit event containment.epoch_bumped_after_restore, so the epoch is above
// anything a gateway cached after the backup was taken. An org without a
// containment row gets one at that epoch. It stops at the first failure;
// running it again raises every epoch again.
func cmdBumpEpochs(ctx context.Context, args []string, stdout, stderr io.Writer, env Env) error {
	const name = "keys bump-epochs"
	var all bool
	cfgPath, confirm, err := operatorFlags(name, args, stderr, &all)
	if err != nil {
		return err
	}
	if !all {
		_, _ = fmt.Fprintln(stderr, "keys bump-epochs needs --all (every organization)")
		return errUsage
	}
	if !confirm {
		return errors.New("keys bump-epochs: raises every organization's containment epoch, so gateways drop their cached state; run again with --confirm")
	}
	_, pool, err := openOperatorPool(ctx, cfgPath, stderr, env, name)
	if err != nil {
		return err
	}
	defer pool.Close()
	orgs, err := pool.CrossOrgListAll(ctx, db.ListAllOrgs, epochPageSize)
	if err != nil {
		return err
	}
	actor := evdomain.Actor{Type: "operator", ID: operatorName()}
	skipped := 0
	for i, o := range orgs {
		from, to, err := bumpEpochAfterRestore(ctx, pool, o.Org, actor)
		if err != nil {
			return fmt.Errorf("%s: org %s (%d of %d done): %w", name, o.Org, i, len(orgs), err)
		}
		if from == "deleted" {
			skipped++
			_, _ = fmt.Fprintf(stdout, "org %s: skipped irreversible DELETED organization (no writes)\n", o.Org)
			continue
		}
		_, _ = fmt.Fprintf(stdout, "org %s: epoch %s -> %d\n", o.Org, from, to)
	}
	_, _ = fmt.Fprintf(stdout, "raised the containment epoch of %d organization(s)\n", len(orgs)-skipped)
	_, _ = fmt.Fprintf(stdout, "skipped %d irreversible DELETED organization(s)\n", skipped)
	return nil
}

// bumpEpochAfterRestore raises one org's epoch and audits it in one
// transaction. from is "none" for a missing containment row, or "deleted"
// when an irreversible DELETED org was read without writing anything.
func bumpEpochAfterRestore(ctx context.Context, pool *db.Pool, org ids.OrgID, actor evdomain.Actor) (from string, to int64, err error) {
	err = pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		from = "none"
		var state string
		if err := tx.QueryRow(ctx, "SELECT state FROM pc.orgs WHERE id=$1", org).Scan(&state); err != nil {
			return err
		}
		if state == "DELETED" {
			from = "deleted"
			return nil
		}
		var prev int64
		err := tx.QueryRow(ctx, "SELECT epoch FROM pc.org_containment WHERE org_id = $1 FOR UPDATE", org).Scan(&prev)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
		case err != nil:
			return err
		default:
			from = strconv.FormatInt(prev, 10)
		}
		if err := tx.QueryRow(ctx, `
			INSERT INTO pc.org_containment (org_id, epoch)
			VALUES ($1, (extract(epoch FROM clock_timestamp()) * 1000)::bigint)
			ON CONFLICT (org_id) DO UPDATE
			SET epoch = greatest(pc.org_containment.epoch + 1, EXCLUDED.epoch), updated_at = now()
			RETURNING epoch`, org).Scan(&to); err != nil {
			return err
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: "containment.epoch_bumped_after_restore", Actor: actor, Outcome: audit.Success,
			Object:  &audit.Object{Type: "org", ID: org.String()},
			Details: map[string]string{"from": from, "to": strconv.FormatInt(to, 10)},
		})
		return err
	})
	return from, to, err
}
