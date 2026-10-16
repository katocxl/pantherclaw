// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package ports holds the governed-automation ports that take a
// transaction (G0 M11 part 2 D11), like internal/reflex/ports: domain
// packages stay pure (ARCHITECTURE §4, no pgx), so the interfaces whose
// methods take a pgx.Tx live here and their value types in autodomain.
// Implementations are wired in internal/server.
//
// Import it as autoports.
package ports

import (
	"context"

	"github.com/jackc/pgx/v5"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Starter starts an execution for an accepted trigger in the caller's
// transaction (engine, D24). It returns the execution id, or
// autodomain.ErrConcurrency or autodomain.ErrNotActive.
type Starter interface {
	Start(ctx context.Context, tx pgx.Tx, t autodomain.TriggerRef) (ids.UUID, error)
}

// TriggerActivator materializes and retires an automation's triggers
// (triggers, D17, D23).
type TriggerActivator interface {
	Activate(ctx context.Context, tx pgx.Tx, automation, version ids.UUID) error
	Deactivate(ctx context.Context, tx pgx.Tx, automation ids.UUID, policy autodomain.PausedTriggers) error
	// Resume replays unexpired queued triggers through Starter (which
	// revalidates); never a missed schedule occurrence whose policy is SKIP.
	Resume(ctx context.Context, tx pgx.Tx, automation ids.UUID) (replayed int, err error)
}

// Pauser pauses ACTIVE automations in the caller's transaction and returns
// the ones it paused (core, D14, D31).
type Pauser interface {
	Pause(ctx context.Context, tx pgx.Tx, org ids.OrgID, sel autodomain.PauseSelector, reason autodomain.PauseReason) ([]ids.UUID, error)
}

// Deliverer queues and reports webhook deliveries (triggers, D22).
type Deliverer interface {
	Deliver(ctx context.Context, tx pgx.Tx, d autodomain.Delivery) (ids.UUID, error)
	Status(ctx context.Context, tx pgx.Tx, id ids.UUID) (autodomain.DeliveryStatus, error)
}

// TestGate reports whether a version passed its scenario tests for this
// digest (assurance, D34). A nil TestGate passes nothing.
type TestGate interface {
	Passed(ctx context.Context, tx pgx.Tx, version ids.UUID, digest []byte) (run ids.UUID, ok bool, err error)
}

// RolloutEvidence reports whether a COHORT stage may widen to FULL
// (assurance, D36). A nil RolloutEvidence verifies nothing.
type RolloutEvidence interface {
	Verified(ctx context.Context, tx pgx.Tx, automation, version ids.UUID) (bool, []string, error)
}

// CeilingChecker revalidates a ceiling's approvers: each active, still
// holding automation.publish and every confirmer permission at every scope
// it covers, and not compromised (core, D9, HR-273). It returns a stable
// reason when the ceiling no longer holds.
type CeilingChecker interface {
	Check(ctx context.Context, tx pgx.Tx, c autodomain.CeilingCheck) (ok bool, reason string, err error)
}

// CompromiseChecker reports whether a person is marked compromised
// (protect, D43). A nil CompromiseChecker reports nobody.
type CompromiseChecker interface {
	Compromised(ctx context.Context, tx pgx.Tx, org ids.OrgID, user ids.UUID) (bool, error)
}

// Step is one catalog kind's runtime (D11). Run starts an attempt, Poll
// re-checks a WAITING one, Preview returns the would-be result without
// effects (SHADOW, TEST, simulation; HR-288).
type Step interface {
	Kind() string
	Run(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error)
	Poll(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error)
	Preview(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error)
}

// StepRegistry maps catalog kinds to their runtimes; built in server
// wiring from the generic and security steps.
type StepRegistry map[string]Step
