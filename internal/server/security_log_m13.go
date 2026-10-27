// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/securityevent"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

func cmdSecurityLog(ctx context.Context, args []string, stdout, stderr io.Writer, env Env) error {
	if len(args) == 0 || (args[0] != "export" && args[0] != "ack") {
		return errUsage
	}
	action := args[0]
	fs := flag.NewFlagSet("security-log "+action, flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "JSON configuration file")
	orgRaw := fs.String("org", "", "event organization UUID")
	out := fs.String("out", "", "new exclusive NDJSON file (export only)")
	after := fs.Int64("after", 0, "export events after this ledger sequence")
	limit := fs.Int("limit", securityevent.OutboxBatch, "maximum export page size, 1..500")
	through := fs.Int64("through", 0, "verified durable external copy includes every security event through this sequence")
	confirm := fs.Bool("confirm", false, "confirm the complete prefix has a verified durable external copy")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	org, err := ids.Parse[ids.Org](*orgRaw)
	if err != nil || fs.NArg() != 0 {
		return errUsage
	}
	if action == "export" && (*out == "" || *through != 0 || *confirm || *after < 0 || *limit < 1 || *limit > securityevent.OutboxBatch) {
		return errUsage
	}
	if action == "ack" && (*through < 1 || *out != "" || *after != 0 || *limit != securityevent.OutboxBatch) {
		return errUsage
	}
	if action == "ack" && !*confirm {
		return errors.New("security-log ack requires --confirm only after verifying a durable external copy of every security event through --through; local emission/export is not acknowledgement")
	}
	_, pool, err := openOperatorPool(ctx, *configPath, stderr, env, "security-log "+action)
	if err != nil {
		return err
	}
	defer pool.Close()
	if action == "ack" {
		err = pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			count, err := securityevent.AcknowledgeIn(ctx, tx, *through)
			if err != nil {
				return err
			}
			_, err = audit.Record(ctx, tx, audit.Event{Name: "security_log.acknowledged", Actor: domain.Actor{Type: "operator", ID: operatorName()}, Outcome: audit.Success, Object: &audit.Object{Type: "org", ID: org.String()}, Details: map[string]string{"through_seq": strconv.FormatInt(*through, 10), "count": strconv.FormatInt(count, 10)}})
			return err
		})
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(stdout, "acknowledged operator-verified durable security-event prefix through %d; rows retained\n", *through)
		return err
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("security-log export: exclusive output: %w", err)
	}
	n, last, writeErr := securityevent.Export(ctx, pool, org, *after, *limit, f)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	closeErr := f.Close()
	if writeErr != nil {
		return fmt.Errorf("security-log export: partial file is not a durable copy: %w", writeErr)
	}
	if closeErr != nil {
		return closeErr
	}
	_, err = fmt.Fprintf(stdout, "exported %d event(s) through sequence %d; fsynced file; no events acknowledged\n", n, last)
	return err
}
