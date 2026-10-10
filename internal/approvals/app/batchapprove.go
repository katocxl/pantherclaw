// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"slices"
	"strconv"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/katocxl/pantherclaw/internal/actionir"
	pgapprovals "github.com/katocxl/pantherclaw/internal/approvals/adapters/pgapprovals"
	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// Definitions reads a pinned definition in the caller's transaction
// (definitions/adapters/pgstore.Store), for batch approval's reversibility
// and value.
type Definitions interface {
	PinnedInTx(ctx context.Context, tx db.TenantTx, org ids.OrgID, pin actionir.Definition) (*defs.Definition, defs.State, error)
}

// errNoDefinitions is a wiring error: batch approval reads definitions.
var errNoDefinitions = errors.New("approvals: batch approval needs the definitions store")

// notBatchable refuses a request that must be reviewed alone, with why.
func notBatchable(why string) error {
	return pcerr.New(pcerr.FailedPrecondition, why, "this request must be reviewed on its own")
}

// sortedBatch checks 1 to 25 different requests and returns them in id
// order, the order every batch locks them in.
func sortedBatch(requests []ids.UUID) ([]ids.UUID, error) {
	sorted := slices.Clone(requests)
	slices.SortFunc(sorted, func(a, b ids.UUID) int { return bytes.Compare(a[:], b[:]) })
	if len(sorted) == 0 || len(sorted) > apdomain.MaxBatch || len(slices.Compact(slices.Clone(sorted))) != len(sorted) {
		return nil, ErrBatchInvalid
	}
	return sorted, nil
}

// batchItem checks one request of a batch approval for user (decision 9):
// it is a held action the user may approve now (with cred, when given) and
// batchable. It returns the locked request, its binding and the key every
// request of the batch shares (operation and definition digest).
func (s *Service) batchItem(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, id, user, cred ids.UUID,
	ceilings map[string]string,
) (locked, [32]byte, string, error) {
	var binding [32]byte
	row, err := q.GetApprovalRequestForUpdate(ctx, org, id)
	if db.IsNoRows(err) {
		return locked{}, binding, "", ErrNotFound
	} else if err != nil {
		return locked{}, binding, "", err
	}
	if row.SubjectKind != subjectAction {
		return locked{}, binding, "", notBatchable(apdomain.BatchNotAHold)
	}
	if err := approvable(ctx, q, org, row, user); err != nil {
		return locked{}, binding, "", err
	}
	e, err := pgapprovals.LoadEligibility(ctx, q, org, id, []ids.UUID{user})
	if err != nil {
		return locked{}, binding, "", err
	}
	if !cred.IsZero() && len(e.Requirements) > 0 {
		if ok, _ := apdomain.Check(e.Requirements[0], e.People[user], e.Context, cred); !ok {
			return locked{}, binding, "", ErrNotEligible
		}
	}
	var a actionir.ActionIR
	if err := json.Unmarshal(row.ActionIr, &a); err != nil {
		return locked{}, binding, "", notBatchable(apdomain.BatchNotAHold)
	}
	if s.Defs == nil {
		return locked{}, binding, "", errNoDefinitions
	}
	d, _, err := s.Defs.PinnedInTx(ctx, tx, org, a.Definition)
	if err != nil {
		return locked{}, binding, "", err
	}
	vals, err := d.DecodeParams(a.Params)
	if err != nil {
		return locked{}, binding, "", notBatchable(apdomain.BatchNoValue)
	}
	if ok, why := apdomain.Batchable(e.Requirements, string(d.Reversibility), singleMoney(vals), ceilings); !ok {
		return locked{}, binding, "", notBatchable(why)
	}
	copy(binding[:], row.Binding)
	return locked{row: row, elig: e}, binding, row.Operation + " " + a.Definition.Digest, nil
}

// singleMoney is an action's value: its one money parameter, or nil.
func singleMoney(vals defs.Values) *money.Money {
	var found *money.Money
	for _, v := range vals {
		if v.Type != defs.TypeMoney {
			continue
		}
		if found != nil {
			return nil
		}
		m := v.Money
		found = &m
	}
	return found
}

func batchCeilings(ctx context.Context, q *dbq.Queries, org ids.OrgID) (map[string]string, error) {
	s, err := q.GetWaitlistSettings(ctx, org)
	if db.IsNoRows(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	out := map[string]string{}
	return out, json.Unmarshal(s.BatchCeilings, &out)
}

// BeginBatch checks a batch approval before the approval page starts its
// BINDING ceremony (HR-175, decision 9, Team edition): 1 to 25 held actions
// of one operation and definition, each one the person may approve now and
// batchable. It records the batch and returns it with its challenge, the
// hash of exactly those bindings.
func (s *Service) BeginBatch(ctx context.Context, orgID ids.OrgID, r Responder, requests []ids.UUID) (ids.UUID, [32]byte, error) {
	var hash [32]byte
	if err := s.teamWaitlist(ctx); err != nil {
		return ids.UUID{}, hash, err
	}
	if r.Browser.IsZero() || r.User.IsZero() {
		return ids.UUID{}, hash, ErrHumanSession
	}
	sorted, err := sortedBatch(requests)
	if err != nil {
		return ids.UUID{}, hash, err
	}
	batch := ids.NewV7()
	err = s.Pool.InTenantTx(ctx, orgID, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		ceilings, err := batchCeilings(ctx, q, orgID)
		if err != nil {
			return err
		}
		bindings, key := make([][32]byte, 0, len(sorted)), ""
		for _, id := range sorted {
			_, b, k, err := s.batchItem(ctx, tx, q, orgID, id, r.User, ids.UUID{}, ceilings)
			if err != nil {
				return err
			}
			if key != "" && k != key {
				return ErrBatchInvalid
			}
			key, bindings = k, append(bindings, b)
		}
		h, err := apdomain.BatchChallenge(bindings)
		if err != nil {
			return err
		}
		hash = h.Hash
		return q.InsertApprovalBatch(ctx, dbq.InsertApprovalBatchParams{
			OrgID: orgID, ID: batch, Kind: "APPROVE", UserID: r.User, SessionID: &r.Browser, BatchHash: hash[:],
			RequestIds: sorted, State: "PENDING",
		})
	})
	return batch, hash, err
}

// ApproveBatch records a batch approval from the approval page (HR-175):
// in one transaction it consumes the batch's BINDING ceremony, checks every
// request again with the credential used and that the batch still covers
// exactly their bindings, and gives each request its own APPROVE response,
// audit event and approval; each is consumed later on its own.
func (s *Service) ApproveBatch(ctx context.Context, orgID ids.OrgID, r Responder, batch ids.UUID, a Assertion) ([]Request, error) {
	if err := s.teamWaitlist(ctx); err != nil {
		return nil, err
	}
	if r.Browser.IsZero() || r.User.IsZero() {
		return nil, ErrHumanSession
	}
	var out []Request
	err := s.Pool.InTenantTx(ctx, orgID, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		n, err := q.ConsumeBatchCeremony(ctx, dbq.ConsumeBatchCeremonyParams{
			OrgID: orgID, ID: a.Ceremony, BatchID: &batch, UserID: r.User, SessionID: r.Browser,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrCeremony
		}
		b, err := q.LockApprovalBatch(ctx, orgID, batch, r.User)
		if db.IsNoRows(err) {
			return ErrCeremony
		} else if err != nil {
			return err
		}
		ceilings, err := batchCeilings(ctx, q, orgID)
		if err != nil {
			return err
		}
		items, bindings, key := make([]locked, 0, len(b.RequestIds)), make([][32]byte, 0, len(b.RequestIds)), ""
		for _, id := range b.RequestIds {
			l, binding, k, err := s.batchItem(ctx, tx, q, orgID, id, r.User, a.Credential, ceilings)
			if err != nil {
				return err
			}
			if key != "" && k != key {
				return ErrBatchInvalid
			}
			key, items, bindings = k, append(items, l), append(bindings, binding)
		}
		h, err := apdomain.BatchChallenge(bindings)
		if err != nil || !bytes.Equal(h.Hash[:], b.BatchHash) {
			return ErrNotWaiting
		}
		for _, l := range items {
			if err := q.InsertApprovalResponse(ctx, dbq.InsertApprovalResponseParams{
				OrgID: orgID, ID: ids.NewV7(), RequestID: l.row.ID, UserID: r.User, SessionID: &r.Browser, Kind: "APPROVE",
				Requirement: pgtype.Int2{Int16: 0, Valid: true}, CredentialID: &a.Credential, AuthenticatorData: a.AuthenticatorData,
				ClientDataJson: a.ClientDataJSON, Signature: a.Signature, BatchID: &batch,
			}); err != nil {
				return err
			}
			if err := event(ctx, tx, "approval.response", userActor(r.User), "APPROVE", l.row.ID,
				map[string]string{"batch": batch.String()}); err != nil {
				return err
			}
			counted := []apdomain.Response{{UserID: r.User, CredentialID: a.Credential, Requirement: 0}}
			if err := approved(ctx, tx, q, orgID, l, counted); err != nil {
				return err
			}
			if err := tell(ctx, tx, s.Notify, orgID, l.row.ID, string(apdomain.StateApproved), "approval.decided",
				map[string]string{"outcome": string(apdomain.StateApproved)}); err != nil {
				return err
			}
			row, err := q.GetApprovalRequest(ctx, orgID, l.row.ID)
			if err != nil {
				return err
			}
			out = append(out, row)
		}
		if n, err := q.CompleteApprovalBatch(ctx, orgID, batch); err != nil || n == 0 {
			return orNotWaiting(err)
		}
		return event(ctx, tx, "approval.batch_approved", userActor(r.User), "", batch,
			map[string]string{"requests": strconv.Itoa(len(items))})
	})
	return out, err
}

func orNotWaiting(err error) error {
	if err != nil {
		return err
	}
	return ErrNotWaiting
}
