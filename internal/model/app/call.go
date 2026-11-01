// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
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
	"github.com/katocxl/pantherclaw/internal/platform/page"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Outcome of a finished call that was not refused.
const outcomeOK = "OK"

// Call is one request to draft. The caller has checked its own permission
// and built Catalog from what the person may read.
type Call struct {
	Task    ports.TaskKind
	Text    string
	Schema  jsontext.Value
	Catalog ports.Catalog
	// Parse takes the provider's untrusted output. An error from it refuses
	// the draft, and the call's audit says so (HR-543). It gets the call so a
	// draft it stores can link to it.
	Parse func(call ids.UUID, output []byte) error
}

// Result is a finished call. ID links a stored draft to its call.
type Result struct {
	ID ids.UUID
}

// reservation is a call allowed through the off switches and the caps.
type reservation struct {
	id     ids.UUID
	model  string
	blob   []byte
	tokens int32
}

// promptOverhead covers a call's fixed prompt and the output format's own
// cost, in tokens.
const promptOverhead = 512

// estimate is the tokens a call may spend: a whole answer plus its input, at
// a cautious three bytes a token.
func (c Call) estimate() int32 {
	in := len(c.Text) + len(c.Schema)
	for _, names := range [][]string{c.Catalog.Entities, c.Catalog.OperationGroups, c.Catalog.StepKinds} {
		for _, n := range names {
			in += len(n)
		}
	}
	return int32(ports.MaxOutputTokens + promptOverhead + in/3) //nolint:gosec // bounded by the request's text, schema and catalog
}

// Draft is the one path to a provider. Every off switch and cap is checked
// before anything leaves. The call's row, its reserved tokens and a ledger
// entry are committed first, so a crash still leaves the call on the ledger
// and against the budget (HR-545, D312); it is settled after, outside any
// transaction, so a slow provider holds no database resources. Nothing in
// either entry is the call's text.
func (s *Service) Draft(ctx context.Context, call Call) (Result, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Result{}, err
	}
	if err := s.entitled(ctx); err != nil {
		return Result{}, err
	}
	if !c.Human() {
		return Result{}, ErrHuman
	}
	if !call.Task.Valid() || call.Parse == nil || !ports.ValidText(call.Text) {
		return Result{}, ports.ErrInvalidRequest
	}
	r, err := s.reserve(ctx, c, call.Task, call.estimate())
	if err != nil {
		return Result{}, err
	}
	resp, err := s.invoke(ctx, c.Org, r, call)
	if err == nil {
		if perr := call.Parse(r.id, resp.Output); perr != nil {
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
// two calls cannot both take the last slot, and writes the call with its
// ledger entry. The tokens of calls in flight count. A refusal by a cap
// commits its audit event and leaves no call.
func (s *Service) reserve(ctx context.Context, c tenancy.Caller, task ports.TaskKind, held int32) (reservation, error) {
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
		out = reservation{id: ids.NewV7(), model: row.Model, blob: row.KeyCiphertext, tokens: held}
		if err := q.InsertModelCall(ctx, dbq.InsertModelCallParams{
			OrgID: c.Org, ID: out.id, Actor: c.Actor().Type + ":" + c.Actor().ID, Task: string(task), Model: row.Model, ReservedTokens: held,
		}); err != nil {
			return err
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: "model.call.started", Actor: c.Actor(), Outcome: audit.Success,
			Object:  &audit.Object{Type: "model_call", ID: out.id.String()},
			Details: map[string]string{"task": string(task), "model": row.Model, "reserved": strconv.Itoa(int(held))},
		})
		return err
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
		Schema: call.Schema, Catalog: call.Catalog,
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

// held is what stays reserved once a call ended: nothing when its usage is
// known or the provider said no, and all of it when the call ended with no
// whole answer, so a timeout cannot be repeated for free (D312).
func (r reservation) held(resp ports.DraftResponse, callErr error) int32 {
	switch {
	case callErr == nil, resp.InputTokens+resp.OutputTokens > 0,
		errors.Is(callErr, ports.ErrKeyRejected), errors.Is(callErr, ports.ErrProviderBusy),
		errors.Is(callErr, ports.ErrProviderFailed), errors.Is(callErr, ports.ErrInvalidRequest):
		return 0
	}
	return r.tokens
}

// finish settles the call and audits it: who, what task, which model, how
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
			ReservedTokens: r.held(resp, callErr), OrgID: c.Org, ID: r.id,
		}); err != nil {
			return err
		}
		_, err := audit.Record(ctx, tx, ev)
		return err
	})
}

// LinkDraft marks a stored version as origin=model in tx, with the thresholds
// its reviewer confirms (D309 Q1, D314).
func LinkDraft(ctx context.Context, tx db.TenantTx, org ids.OrgID, version, call ids.UUID, kind string, as []Ambiguity) error {
	raw, err := json.Marshal(as)
	if err != nil {
		return err
	}
	return dbq.New(tx).InsertModelDraft(ctx, dbq.InsertModelDraftParams{OrgID: org, VersionID: version, CallID: call, Kind: kind, Ambiguities: raw})
}

// StoredDraft is a version's origin=model mark.
type StoredDraft struct {
	Version     ids.UUID
	Kind        string
	Origin      string
	Call        ids.UUID
	Ambiguities []Ambiguity
	CreatedAt   time.Time
}

// draftReaders is what reading each kind of stored draft takes.
var draftReaders = map[string]td.Permission{policyKind: td.PermPolicyRead, automationKind: td.PermAutomationRead}

// GetDraft returns a stored draft's mark, for whoever may read that kind of
// version. It reads what was stored, so it works with drafting off.
func (s *Service) GetDraft(ctx context.Context, version ids.UUID) (StoredDraft, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return StoredDraft{}, err
	}
	var out StoredDraft
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		row, err := dbq.New(tx).GetModelDraft(ctx, c.Org, version)
		if db.IsNoRows(err) {
			return ErrDraftNotFound
		}
		if err != nil {
			return err
		}
		if err := c.Require(draftReaders[row.Kind], td.OrgPath(c.Org)); err != nil {
			return err
		}
		out, err = storedDraft(row)
		return err
	}, db.ReadOnly())
	return out, err
}

func storedDraft(row dbq.PcModelDraft) (StoredDraft, error) {
	out := StoredDraft{Version: row.VersionID, Kind: row.Kind, Origin: row.Origin, Call: row.CallID, CreatedAt: row.CreatedAt}
	return out, json.Unmarshal(row.Ambiguities, &out.Ambiguities)
}

// ListDrafts returns a page of stored drafts, newest first, of the kinds the
// caller may read (G0 M22 D8, F834, HR-554). A draft's row holds its mark and
// thresholds; the prompt and the response are not stored.
func (s *Service) ListDrafts(ctx context.Context, pr page.Request) ([]StoredDraft, string, error) {
	if err := s.inEdition(ctx); err != nil {
		return nil, "", err
	}
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return nil, "", err
	}
	var kinds []string
	for kind, need := range draftReaders {
		if c.Can(need, td.OrgPath(c.Org)) {
			kinds = append(kinds, kind)
		}
	}
	if len(kinds) == 0 {
		return nil, "", c.Require(td.PermPolicyRead, td.OrgPath(c.Org))
	}
	var after *ids.UUID
	if !pr.After.IsZero() {
		after = &pr.After
	}
	var out []StoredDraft
	var next string
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListModelDrafts(ctx, dbq.ListModelDraftsParams{OrgID: c.Org, Kinds: kinds, After: after, PageLimit: pr.Limit()})
		if err != nil {
			return err
		}
		rows, next = page.Finish(pr, rows, func(r dbq.PcModelDraft) ids.UUID { return r.VersionID })
		for _, r := range rows {
			d, err := storedDraft(r)
			if err != nil {
				return err
			}
			out = append(out, d)
		}
		return nil
	}, db.ReadOnly())
	return out, next, err
}

// UsageRow is the calls of one task with one outcome: counts and tokens, no
// text and no caller.
type UsageRow struct {
	Task, Outcome                                    string
	Calls, InputTokens, OutputTokens, ReservedTokens int64
}

// Usage sums the organization's model calls since a time, for whoever may
// read the organization (G0 M22 D8, F834, HR-554).
func (s *Service) Usage(ctx context.Context, since time.Time) ([]UsageRow, error) {
	if err := s.inEdition(ctx); err != nil {
		return nil, err
	}
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return nil, err
	}
	if err := c.Require(td.PermOrgRead, td.OrgPath(c.Org)); err != nil {
		return nil, err
	}
	var out []UsageRow
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ModelUsage(ctx, c.Org, since)
		if err != nil {
			return err
		}
		for _, r := range rows {
			out = append(out, UsageRow{
				Task: r.Task, Outcome: r.Outcome, Calls: r.Calls, InputTokens: r.InputTokens, OutputTokens: r.OutputTokens,
				ReservedTokens: r.ReservedTokens,
			})
		}
		return nil
	}, db.ReadOnly())
	return out, err
}
