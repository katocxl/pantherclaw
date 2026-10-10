// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"log/slog"

	"github.com/katocxl/pantherclaw/internal/authority"
	"github.com/katocxl/pantherclaw/internal/authority/adapters/pgauthority"
	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	factspg "github.com/katocxl/pantherclaw/internal/facts/adapters/pgstore"
	grantspg "github.com/katocxl/pantherclaw/internal/grants/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	polpg "github.com/katocxl/pantherclaw/internal/policy/adapters/pgstore"
	policyapp "github.com/katocxl/pantherclaw/internal/policy/app"
)

// newAuthority builds the Transaction Authority on the M4 decision
// pipeline: every read goes through the Postgres reader (definitions,
// published policy, grants and guardrails, facts, budget usage), and the
// Postgres store binds each decision in one transaction. Permits and
// receipts, and action tokens (HR-188), are signed with the server's keys.
func newAuthority(cfg *Config, pool *db.Pool, reg *keys.Registry, kp keys.KeyProvider, log *slog.Logger) (*authority.Service, error) {
	receipts, err := reg.Signer(keys.PurposeReceipts)
	if err != nil {
		return nil, err
	}
	actionTokens, err := reg.Signer(keys.PurposeActionTokens)
	if err != nil {
		return nil, err
	}
	permits, err := reg.Signer(keys.PurposePermits)
	if err != nil {
		return nil, err
	}
	return authority.New(authority.Config{
		Decider: &finalize.Authority{
			Pipeline: &pipeline.Pipeline{Reader: authorityReader(pool)}, Store: &pgauthority.Store{Pool: pool, LockTimeout: cfg.Authority.BudgetLockTimeout.D()},
			Receipts: receipts, Permits: permits, ActionTokens: actionTokens, PermitTTL: cfg.Authority.PermitTTL.D(), Log: log,
			Inputs: replayInputs(pool, kp),
		},
		Logger: log,
	}), nil
}

// authorityReader reads the pipeline's inputs from Postgres.
func authorityReader(pool *db.Pool) *pgauthority.Reader {
	return &pgauthority.Reader{
		Pool: pool, Definitions: &defspg.Store{Pool: pool}, Policies: &polpg.Store{Pool: pool},
		FactStore: &factspg.Store{Pool: pool}, Grants: &grantspg.Store{Pool: pool},
		Limits: celenv.DefaultLimits, Budget: policyapp.DefaultBudget,
	}
}
