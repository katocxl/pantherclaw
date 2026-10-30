// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/jsontext"
	"fmt"
	"strconv"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/model/ports"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// Outcome of a finished call that was not refused.
const outcomeOK = "OK"

// Call is one request to draft. The caller has checked its own permission
// and built Catalogue from what the person may read.
type Call struct {
	Task      ports.TaskKind
	Text      string
	Schema    jsontext.Value
	Catalogue ports.Catalogue
	// Parse takes the provider's untrusted output. An error from it refuses
	// the draft, and the call's audit says so (HR-543).
	Parse func(output []byte) error
}

// Result is a finished call. ID links a stored draft to its call.
type Result struct {
	ID ids.UUID
}

// reservation is a call allowed through the off switches and the caps.
type reservation struct {
	id    ids.UUID
	model string
	blob  []byte
}

// Draft is the one path to a provider. Every off switch and cap is checked
// before anything leaves; the call's row is committed first and finished
// after, outside any transaction, so a slow provider holds no database
// resources. Every call that reached the provider is audited, without its
// text (HR-545).
func (s *Service) Draft(ctx context.Context, call Call) (Result, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Result{}, err
	}
	if err := s.entitled(ctx); err != nil {
		return Result{}, err
	}
	if !call.Task.Valid() || call.Parse == nil {
		return Result{}, ports.ErrInvalidRequest
	}
	r, err := s.reserve(ctx, c, call.Task)
	if err != nil {
		return Result{}, err
	}
	resp, err := s.invoke(ctx, c.Org, r, call)
	if err == nil {
		if perr := call.Parse(resp.Output); perr != nil {
			err = perr
		}
	}
	if ferr := s.finish(context.WithoutCancel(ctx), c, r, call.Task, resp, err); ferr != nil {
		return Result{}, ferr
	}
	if err != nil {
		return Result{}, err
	}
	return Result{ID: r.id}, nil
}

// reserve checks the switches and the caps under the settings row's lock, so
// two calls cannot both take the last slot, and writes the call. A refusal
// by a cap commits its audit event and leaves no call.
func (s *Service) reserve(ctx context.Context, c tenancy.Caller, task ports.TaskKind) (reservation, error) {
	var out reservation
	var refused error
	err := s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		row, err := q.LockModelSettings(ctx, c.Org)
		if db.IsNoRows(err) {
			return ErrOff
		}
		if err != nil {
			return err
		}
		if !row.Enabled {
			return ErrOff
		}
		if len(row.KeyCiphertext) == 0 {
			return ErrNoKey
		}
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		calls, err := q.CountModelCallsSince(ctx, c.Org, now.Add(-time.Minute))
		if err != nil {
			return err
		}
		tokens, err := q.SumModelTokensSince(ctx, c.Org, now.UTC().Truncate(24*time.Hour))
		if err != nil {
			return err
		}
		maxCalls, maxTokens := s.caps(row)
		refused = overCap(calls, tokens, maxCalls, maxTokens)
		if refused != nil {
			_, err := audit.Record(ctx, tx, audit.Event{
				Name: "model.call", Actor: c.Actor(), Outcome: audit.Denied, ReasonCode: pcerr.ReasonOf(refused),
				Object: &audit.Object{Type: "model_settings", ID: c.Org.String()}, Details: map[string]string{"task": string(task), "model": row.Model},
			})
			return err
		}
		out = reservation{id: ids.NewV7(), model: row.Model, blob: row.KeyCiphertext}
		return q.InsertModelCall(ctx, dbq.InsertModelCallParams{
			OrgID: c.Org, ID: out.id, Actor: c.Actor().Type + ":" + c.Actor().ID, Task: string(task), Model: row.Model,
		})
	})
	if err != nil {
		return reservation{}, err
	}
	return out, refused
}

// overCap says which cap, if any, refuses the next call. Reaching a cap
// refuses: the cap is the number of calls or tokens allowed.
func overCap(calls, tokens int64, maxCalls int, maxTokens int64) error {
	switch {
	case calls >= int64(maxCalls):
		return ErrRateCap
	case tokens >= maxTokens:
		return ErrBudgetCap
	}
	return nil
}

func (s *Service) invoke(ctx context.Context, org ids.OrgID, r reservation, call Call) (ports.DraftResponse, error) {
	plain, err := s.Envelope.Decrypt(ctx, s.field(org), SecretPurpose, r.blob)
	if err != nil {
		return ports.DraftResponse{}, fmt.Errorf("model: open key: %w", err)
	}
	return s.Provider.Draft(ctx, ports.DraftRequest{
		Key: pclog.NewSecret(string(plain)), Model: r.model, Task: call.Task, Text: call.Text,
		Schema: call.Schema, Catalogue: call.Catalogue,
	})
}

// outcomeOf is the code a call ended with.
func outcomeOf(err error) string {
	if err == nil {
		return outcomeOK
	}
	if reason := pcerr.ReasonOf(err); reason != "" {
		return reason
	}
	return "MODEL_CALL_FAILED"
}

// finish closes the call and audits it: who, what task, which model, how
// many tokens, how it ended. Never the text sent or returned.
func (s *Service) finish(ctx context.Context, c tenancy.Caller, r reservation, task ports.TaskKind, resp ports.DraftResponse, callErr error) error {
	outcome := outcomeOf(callErr)
	ev := audit.Event{
		Name: "model.call", Actor: c.Actor(), Outcome: audit.Success,
		Object: &audit.Object{Type: "model_call", ID: r.id.String()},
		Details: map[string]string{
			"task": string(task), "model": r.model, "usage_in": strconv.Itoa(resp.InputTokens), "usage_out": strconv.Itoa(resp.OutputTokens),
		},
	}
	if callErr != nil {
		ev.Outcome, ev.ReasonCode = audit.Failure, outcome
	}
	return s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		if _, err := dbq.New(tx).FinishModelCall(ctx, dbq.FinishModelCallParams{
			Outcome: outcome, InputTokens: int32(resp.InputTokens), OutputTokens: int32(resp.OutputTokens), //nolint:gosec // the provider's counts, within a 64 KiB answer's reach
			OrgID: c.Org, ID: r.id,
		}); err != nil {
			return err
		}
		_, err := audit.Record(ctx, tx, ev)
		return err
	})
}

// LinkDraft marks a stored version as origin=model in tx (D309 Q1).
func LinkDraft(ctx context.Context, tx db.TenantTx, org ids.OrgID, version, call ids.UUID, kind string) error {
	return dbq.New(tx).InsertModelDraft(ctx, dbq.InsertModelDraftParams{OrgID: org, VersionID: version, CallID: call, Kind: kind})
}
