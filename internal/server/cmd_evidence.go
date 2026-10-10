// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/checkpoints"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
)

// integrityResetActor is recorded on the reset's audit entry.
var integrityResetActor = evdomain.Actor{Type: "operator", ID: "evidence-integrity-reset"}

// cmdEvidence implements `evidence integrity reset --org ID --reason TEXT
// --confirm [--config FILE]` (G0 M7 design decision 8, HR-194): after an
// operator investigated an org whose evidence integrity FAILED, its status
// is set back to OK, audited with the reason and notified, in one tenant
// transaction as pc_app. Nothing is repaired: the next checkpoint and daily
// verification check the ledger again, and fail again if it is still
// broken. Without --confirm nothing changes.
func cmdEvidence(ctx context.Context, args []string, stdout, stderr io.Writer, env Env) error {
	if len(args) < 2 || args[0] != "integrity" || args[1] != "reset" {
		_, _ = fmt.Fprint(stderr, usage)
		return errUsage
	}
	fs := flag.NewFlagSet("evidence integrity reset", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "JSON configuration file")
	orgFlag := fs.String("org", "", "organization id")
	reason := fs.String("reason", "", "what the investigation found (1..500 bytes; kept in the audit ledger)")
	confirm := fs.Bool("confirm", false, "resume checkpointing of the org: its ledger is checked again")
	if err := fs.Parse(args[2:]); err != nil {
		return err
	}
	if fs.NArg() != 0 || *orgFlag == "" || *reason == "" {
		fs.Usage()
		return errUsage
	}
	org, err := ids.Parse[ids.Org](*orgFlag)
	if err != nil {
		return err
	}
	if !*confirm {
		return errors.New("evidence integrity reset: checkpointing of the org resumes and its ledger is checked again; " +
			"investigate first (docs/runbooks/evidence-verification.md), then run again with --confirm")
	}
	cfg, _, err := loadConfig([]string{"--config", *cfgPath}, stderr, env, "evidence integrity reset")
	if err != nil {
		return err
	}
	log := newLogger(cfg, stderr)
	appCfg, err := cfg.dbConfig(cfg.DB.AppUser, cfg.DB.AppPasswordFile, 2)
	if err != nil {
		return err
	}
	pool, err := db.Open(ctx, appCfg)
	if err != nil {
		return err
	}
	defer pool.Close()
	insert, err := jobs.NewClient(pool, nil, jobs.Config{Logger: log}) // insert-only: the workers deliver
	if err != nil {
		return err
	}
	// Enqueueing renders a fixed template and routes it; it needs no channel
	// secrets, so no envelope.
	notif, err := napp.New(pool, insert, nil, napp.Config{PublicURL: cfg.Auth.PublicURL}, clock.System{}, log)
	if err != nil {
		return err
	}
	svc := &checkpoints.Service{Pool: pool, Notify: notif, Log: log}
	cleared, done, err := svc.Reset(ctx, org, integrityResetActor, *reason)
	if err != nil {
		return fmt.Errorf("evidence integrity reset: %w", err)
	}
	if !done {
		_, _ = fmt.Fprintf(stdout, "the evidence integrity of %s is not FAILED: nothing changed\n", org)
		return nil
	}
	at := ""
	if cleared.Seq > 0 {
		at = fmt.Sprintf(" at seq %d", cleared.Seq)
	}
	_, _ = fmt.Fprintf(stdout, "reset the evidence integrity of %s to OK: it had failed with %s%s on %s; "+
		"audited as evidence.integrity_reset and notified\n", org, cleared.Code, at, cleared.FailedAt.UTC().Format(time.RFC3339))
	_, _ = fmt.Fprintf(stdout, "next:\n"+
		"  - within evidence.checkpoint_interval (%s) the checkpoint job takes the org again (the reset's audit entry grows "+
		"its chain) and verifies its latest checkpoint, the tiles and every chain link since it;\n"+
		"  - within the hour the daily verification walks the whole chain again.\n"+
		"nothing was repaired: if an entry, a tile or a checkpoint is still broken, the org FAILS AGAIN, with a new audit "+
		"entry and notification (docs/runbooks/evidence-verification.md)\n", cfg.checkpointInterval())
	return nil
}
