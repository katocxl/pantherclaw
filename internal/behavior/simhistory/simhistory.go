// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package simhistory gives a range agent a labeled, made-up history, so
// behavior analytics can be shown and tested without weeks of real work
// (G0 M27 D502; F931; HR-642, HR-222, F630). The same seed gives the same
// history. Rows go to pc.behavior_simulated_actions, never pc.transactions,
// and the database refuses them for any agent but a range agent. Nothing
// here is a recording of anything that happened.
package simhistory

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"

	bdomain "github.com/katocxl/pantherclaw/internal/behavior/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// Generator names this generator on every row.
const Generator = "simhistory.v1"

// Spec is what history to make.
type Spec struct {
	Agent      ids.UUID
	Connection ids.UUID
	DestClass  string
	// Operations run in this order within each run.
	Operations []string
	// Runs per day, on Days days before End, around Hour UTC.
	Days, RunsPerDay, Hour int
	End                    time.Time
	// Spend, if set, is one more operation each day that spends Amount.
	SpendOperation string
	Amount         money.Decimal
	Currency       string
	Seed           uint64
}

// Actions makes the history. It is a pure function of the spec.
func Actions(s Spec) []bdomain.Action {
	rng := &stream{seed: s.Seed}
	uuid := func() ids.UUID { return seeded(rng) }
	var out []bdomain.Action
	day := s.End.UTC().Truncate(24 * time.Hour)
	for d := s.Days; d >= 1; d-- {
		base := day.AddDate(0, 0, -d).Add(time.Duration(s.Hour) * time.Hour)
		for r := range s.RunsPerDay {
			run := uuid()
			at := base.Add(time.Duration(r*7+int(rng.next()%5)) * time.Minute)
			for i, op := range s.Operations {
				out = append(out, bdomain.Action{
					ID: uuid(), Agent: s.Agent, Run: run, Operation: op, Connection: s.Connection, DestClass: s.DestClass,
					At: at.Add(time.Duration(i) * time.Minute), Generated: true, Known: true,
				})
			}
		}
		if s.SpendOperation != "" {
			amount := s.Amount
			out = append(out, bdomain.Action{
				ID: uuid(), Agent: s.Agent, Run: uuid(), Operation: s.SpendOperation, Connection: s.Connection, DestClass: s.DestClass,
				At: base.Add(30 * time.Minute), Spent: &amount, Currency: s.Currency, Generated: true, Known: true,
			})
		}
	}
	return out
}

// stream is a repeatable byte stream: SHA-256 of the seed and a counter.
// Made-up history must repeat for a seed, so it is derived, not random;
// nothing about it is secret.
type stream struct {
	seed, n uint64
	buf     []byte
}

func (r *stream) next() byte {
	if len(r.buf) == 0 {
		var in [16]byte
		binary.BigEndian.PutUint64(in[:8], r.seed)
		binary.BigEndian.PutUint64(in[8:], r.n)
		r.n++
		sum := sha256.Sum256(in[:])
		r.buf = sum[:]
	}
	b := r.buf[0]
	r.buf = r.buf[1:]
	return b
}

// seeded is a repeatable version 4 UUID.
func seeded(rng *stream) ids.UUID {
	var b [16]byte
	for i := range b {
		b[i] = rng.next()
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return ids.UUID(b)
}

// Store writes the history of s. The database refuses an agent that isn't a
// range agent (HR-642).
func Store(ctx context.Context, tx db.TenantTx, s Spec) (int, error) {
	q := dbq.New(tx)
	as := Actions(s)
	for _, a := range as {
		p := dbq.InsertBehaviorSimulatedActionParams{
			OrgID: tx.OrgID(), ID: a.ID, AgentID: a.Agent, RunRef: a.Run, Operation: a.Operation, DestinationClass: a.DestClass,
			OccurredAt: a.At, Generator: Generator, Seed: int64(s.Seed), //nolint:gosec // a label, wrapping is harmless
		}
		if !a.Connection.IsZero() {
			c := a.Connection
			p.ConnectionID = &c
		}
		if a.Spent != nil {
			cur := a.Currency
			p.Amount, p.Currency = a.Spent, &cur
		}
		if err := q.InsertBehaviorSimulatedAction(ctx, p); err != nil {
			return 0, fmt.Errorf("simhistory: %w", err)
		}
	}
	return len(as), nil
}
