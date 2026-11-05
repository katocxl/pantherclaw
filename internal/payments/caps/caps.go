// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package caps holds an org's merchant caps for agent payments (G0 M39
// D1124, D1124a; FQ39-2; HR-835, HR-836). Every agent payment holds for a
// person by default; an ACTIVE cap lets payments to one merchant, in one
// currency, go through without a person while each is at most the cap's
// per-payment limit and the UTC day's total of such payments stays at most
// its per-day limit. Anything over holds for a person; nothing here ever
// refuses a payment.
//
// A cap is proposed DRAFT by a person holding payments.manage, with a
// PAYMENT_CAP change request; creating or raising a cap is a loosening, so
// it becomes ACTIVE only when two distinct people confirm the request with
// distinct security keys on the policy changes page. Apply, the request's
// apply callback, voids a request that one person alone could confirm
// (TWO_PEOPLE_REQUIRED). Activating a cap retires the merchant's earlier
// ACTIVE cap in that currency. Retiring needs payments.manage and a person.
package caps

import (
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"regexp"
	"strconv"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	papp "github.com/katocxl/pantherclaw/internal/policy/app"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// Cap states.
const (
	StateDraft   = "DRAFT"
	StateActive  = "ACTIVE"
	StateRetired = "RETIRED"
)

// MaxMinor bounds a cap's limits, in minor units.
const MaxMinor = 100_000_000_000

// MerchantRe is a normalized merchant id: lowercase, as the pc.agentpay
// merchant param spells it.
var MerchantRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,127}$`)

var currencyRe = regexp.MustCompile(`^[A-Z]{3}$`)

// Errors.
var (
	ErrNotFound = pcerr.New(pcerr.NotFound, "PAYMENT_CAP_NOT_FOUND", "merchant cap not found")
	ErrInvalid  = pcerr.New(pcerr.InvalidArgument, "PAYMENT_CAP_INVALID",
		"a cap names a lowercase merchant id, an ISO 4217 currency, and limits of 1 to 100000000000 minor units, the per-payment limit at most the per-day one")
	ErrHumanOnly = pcerr.New(pcerr.PermissionDenied, "HUMAN_ONLY", "only a person can do this")
	// ErrGateUnavailable: no change requests are wired, so no cap can be
	// proposed (fail closed).
	ErrGateUnavailable = pcerr.New(pcerr.FailedPrecondition, "PAYMENT_CAP_GATE_UNAVAILABLE",
		"merchant caps need the policy change gate, which is not available")
)

// Cap is one merchant cap.
type Cap struct {
	ID                 ids.UUID
	Merchant           string
	Currency           string
	MaxPerPaymentMinor int64
	MaxPerDayMinor     int64
	State              string
	CreatedBy          string
	CreatedAt          time.Time
	ChangeRequest      ids.UUID // zero: none yet
	ChangeRequestURL   string
	ApprovedBy         []ids.UUID
	ActivatedAt        *time.Time
	RetiredAt          *time.Time
	RetiredBy          string
}

// Active is the ACTIVE cap of one merchant in one currency, as the payment
// step reads it.
type Active struct {
	ID                 ids.UUID
	MaxPerPaymentMinor int64
	MaxPerDayMinor     int64
}

// ChangeRequester creates the PAYMENT_CAP change request whose approval
// activates the cap (papp.Changes, with Apply registered for
// papp.ChangePaymentCap).
type ChangeRequester interface {
	Request(ctx context.Context, kind papp.ChangeKind, subjectID, baseVersionID ids.UUID, binding [32]byte, summary any) (papp.ChangeRequest, error)
	URL(org ids.OrgID, id ids.UUID) string
}

// Service runs the merchant cap use cases. Permissions are checked by the
// RPC interceptor (payments.manage, payments.read); Service checks that
// changes come from a person.
type Service struct {
	Pool    *db.Pool
	Changes ChangeRequester
	// Editions reports the licence; nil: no cap can be proposed (agent
	// payments are Business edition; fail closed).
	Editions Editions
}

// Editions reports the licence's entitlements.
type Editions interface {
	Current(ctx context.Context) (billing.Entitlements, error)
}

// ErrEdition: proposing a merchant cap needs the Business edition. Caps
// already ACTIVE keep applying; reading and retiring work in every edition.
var ErrEdition = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED", "agent payments need the Business edition")

func (s *Service) business(ctx context.Context) error {
	if s.Editions == nil {
		return ErrEdition
	}
	e, err := s.Editions.Current(ctx)
	if err != nil {
		return err
	}
	if e.Edition != billing.Business && e.Edition != billing.Enterprise {
		return ErrEdition
	}
	return nil
}

// Proposal is what a person proposes.
type Proposal struct {
	Merchant           string
	Currency           string
	MaxPerPaymentMinor int64
	MaxPerDayMinor     int64
}

func (p Proposal) valid() bool {
	return MerchantRe.MatchString(p.Merchant) && currencyRe.MatchString(p.Currency) &&
		p.MaxPerPaymentMinor >= 1 && p.MaxPerDayMinor >= 1 && p.MaxPerPaymentMinor <= MaxMinor && p.MaxPerDayMinor <= MaxMinor &&
		p.MaxPerPaymentMinor <= p.MaxPerDayMinor
}

// summary is what the confirmers see and sign (through the binding).
type summary struct {
	Kind               string `json:"kind"`
	Cap                string `json:"cap"`
	Merchant           string `json:"merchant"`
	Currency           string `json:"currency"`
	MaxPerPaymentMinor string `json:"max_per_payment_minor"`
	MaxPerDayMinor     string `json:"max_per_day_minor"`
	Replaces           string `json:"replaces,omitzero"`
	ReplacesPerPayment string `json:"replaces_max_per_payment_minor,omitzero"`
	ReplacesPerDay     string `json:"replaces_max_per_day_minor,omitzero"`
}

// contentDigest is the digest the change binding carries: the cap's exact
// merchant, currency and limits.
func contentDigest(id ids.UUID, p Proposal) [32]byte {
	raw, _ := json.Marshal(map[string]string{
		"cap": id.String(), "merchant": p.Merchant, "currency": p.Currency,
		"max_per_payment_minor": strconv.FormatInt(p.MaxPerPaymentMinor, 10),
		"max_per_day_minor":     strconv.FormatInt(p.MaxPerDayMinor, 10),
	}, json.Deterministic(true))
	return sha256.Sum256(raw)
}

func person(ctx context.Context) (tapp.Caller, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return tapp.Caller{}, err
	}
	if !c.Human() {
		return tapp.Caller{}, ErrHumanOnly
	}
	return c, nil
}

func record(ctx context.Context, tx db.TenantTx, c tapp.Caller, name string, id ids.UUID, details map[string]string) error {
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: c.Actor(), Outcome: audit.Success, Object: &audit.Object{Type: "payment_merchant_cap", ID: id.String()},
		Details: details,
	})
	return err
}

// Propose adds a DRAFT cap and its PAYMENT_CAP change request (a person
// only). The request names the merchant's current ACTIVE cap it would
// replace, if any, so the confirmers see what changes.
func (s *Service) Propose(ctx context.Context, p Proposal) (Cap, error) {
	c, err := person(ctx)
	if err != nil {
		return Cap{}, err
	}
	if err := s.business(ctx); err != nil {
		return Cap{}, err
	}
	if !p.valid() {
		return Cap{}, ErrInvalid
	}
	if s.Changes == nil || s.Pool == nil {
		return Cap{}, ErrGateUnavailable
	}
	id := ids.NewV7()
	sum := summary{
		Kind: string(papp.ChangePaymentCap), Cap: id.String(), Merchant: p.Merchant, Currency: p.Currency,
		MaxPerPaymentMinor: strconv.FormatInt(p.MaxPerPaymentMinor, 10), MaxPerDayMinor: strconv.FormatInt(p.MaxPerDayMinor, 10),
	}
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		switch cur, err := q.ActivePaymentMerchantCap(ctx, c.Org, p.Merchant, p.Currency); {
		case db.IsNoRows(err):
		case err != nil:
			return err
		default:
			sum.Replaces = cur.ID.String()
			sum.ReplacesPerPayment = strconv.FormatInt(cur.MaxPerPaymentMinor, 10)
			sum.ReplacesPerDay = strconv.FormatInt(cur.MaxPerDayMinor, 10)
		}
		if err := q.InsertPaymentMerchantCap(ctx, dbq.InsertPaymentMerchantCapParams{
			OrgID: c.Org, ID: id, Merchant: p.Merchant, Currency: p.Currency,
			MaxPerPaymentMinor: p.MaxPerPaymentMinor, MaxPerDayMinor: p.MaxPerDayMinor, CreatedBy: c.Principal.ID.String(),
		}); err != nil {
			return err
		}
		return record(ctx, tx, c, auditkind.PaymentsCapProposed, id, map[string]string{
			"merchant": p.Merchant, "currency": p.Currency,
			"max_per_payment_minor": sum.MaxPerPaymentMinor, "max_per_day_minor": sum.MaxPerDayMinor, "replaces": sum.Replaces,
		})
	})
	if err != nil {
		return Cap{}, err
	}
	binding, err := papp.ChangeBinding(papp.ChangePaymentCap, c.Org, id, ids.UUID{}, contentDigest(id, p), sum)
	if err != nil {
		return Cap{}, err
	}
	req, err := s.Changes.Request(ctx, papp.ChangePaymentCap, id, ids.UUID{}, binding, sum)
	if err != nil {
		// The DRAFT stays unconfirmable without a request: retire it, so a
		// failed proposal leaves nothing pending.
		if rerr := s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
			_, err := dbq.New(tx).RetirePaymentMerchantCap(ctx,
				new(c.Principal.ID.String()), c.Org, id)
			return err
		}); rerr != nil {
			return Cap{}, errors.Join(err, rerr)
		}
		return Cap{}, err
	}
	out, err := s.get(ctx, c.Org, id)
	if err == nil {
		out.ChangeRequest, out.ChangeRequestURL = req.ID, req.URL
		if out.ChangeRequestURL == "" {
			out.ChangeRequestURL = s.Changes.URL(c.Org, req.ID)
		}
	}
	return out, err
}

// Apply is the PAYMENT_CAP change request's apply callback, run in the
// transaction that approves it. A request that fewer than two people
// confirm is voided (TWO_PEOPLE_REQUIRED): a cap is never activated by one
// person alone (HR-836). A cap that is no longer DRAFT voids the request.
// Otherwise the merchant's earlier ACTIVE cap in that currency is retired
// and this one becomes ACTIVE, with every confirmer as an approver.
func (s *Service) Apply(ctx context.Context, tx db.TenantTx, req papp.ChangeRequest) error {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return err
	}
	if req.Required < 2 {
		return &papp.VoidError{Reason: papp.VoidTwoPeopleRequired}
	}
	approvers := make([]ids.UUID, 0, len(req.Confirmations)+1)
	for _, x := range req.Confirmations {
		approvers = append(approvers, x.Principal)
	}
	approvers = append(approvers, c.Principal.ID)
	distinct := map[ids.UUID]bool{}
	for _, a := range approvers {
		distinct[a] = true
	}
	if len(distinct) < 2 {
		return &papp.VoidError{Reason: papp.VoidTwoPeopleRequired}
	}
	q := dbq.New(tx)
	cp, err := q.LockPaymentMerchantCap(ctx, c.Org, req.Subject)
	if db.IsNoRows(err) {
		return &papp.VoidError{Reason: papp.VoidBaseChanged}
	} else if err != nil {
		return err
	}
	if cp.State != StateDraft {
		return &papp.VoidError{Reason: papp.VoidBaseChanged}
	}
	switch cur, err := q.ActivePaymentMerchantCap(ctx, c.Org, cp.Merchant, cp.Currency); {
	case db.IsNoRows(err):
	case err != nil:
		return err
	default:
		if _, err := q.RetireActivePaymentMerchantCaps(ctx, dbq.RetireActivePaymentMerchantCapsParams{
			RetiredBy: new("change_request:" + req.ID.String()), OrgID: c.Org, Merchant: cp.Merchant, Currency: cp.Currency,
		}); err != nil {
			return err
		}
		if err := record(ctx, tx, c, auditkind.PaymentsCapRetired, cur.ID, map[string]string{
			"replaced_by": cp.ID.String(), "change_request": req.ID.String(),
		}); err != nil {
			return err
		}
	}
	n, err := q.ActivatePaymentMerchantCap(ctx, dbq.ActivatePaymentMerchantCapParams{
		ChangeRequestID: &req.ID, ApprovedBy: approvers, OrgID: c.Org, ID: cp.ID,
	})
	if err != nil {
		return err
	}
	if n != 1 {
		return &papp.VoidError{Reason: papp.VoidBaseChanged}
	}
	return record(ctx, tx, c, auditkind.PaymentsCapActivated, cp.ID, map[string]string{
		"merchant": cp.Merchant, "currency": cp.Currency, "change_request": req.ID.String(),
		"max_per_payment_minor": strconv.FormatInt(cp.MaxPerPaymentMinor, 10),
		"max_per_day_minor":     strconv.FormatInt(cp.MaxPerDayMinor, 10),
		"approvers":             strconv.Itoa(len(distinct)),
	})
}

// Retire retires a cap for good (a person only).
func (s *Service) Retire(ctx context.Context, id ids.UUID) (Cap, error) {
	c, err := person(ctx)
	if err != nil {
		return Cap{}, err
	}
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		n, err := q.RetirePaymentMerchantCap(ctx,
			new(c.Principal.ID.String()), c.Org, id)
		if err != nil {
			return err
		}
		if n == 0 {
			if _, err := q.GetPaymentMerchantCap(ctx, c.Org, id); db.IsNoRows(err) {
				return ErrNotFound
			} else if err != nil {
				return err
			}
			return nil // already RETIRED
		}
		return record(ctx, tx, c, auditkind.PaymentsCapRetired, id, nil)
	})
	if err != nil {
		return Cap{}, err
	}
	return s.get(ctx, c.Org, id)
}

// Filter narrows a listing.
type Filter struct {
	State    *string
	Merchant *string
}

// List lists caps by id.
func (s *Service) List(ctx context.Context, f Filter, size int32, token string) ([]Cap, string, error) {
	p, err := page.Parse(size, token)
	if err != nil {
		return nil, "", err
	}
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return nil, "", err
	}
	var out []Cap
	var next string
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		var after *ids.UUID
		if !p.After.IsZero() {
			after = &p.After
		}
		rows, err := dbq.New(tx).ListPaymentMerchantCaps(ctx, dbq.ListPaymentMerchantCapsParams{
			OrgID: c.Org, State: f.State, Merchant: f.Merchant, AfterID: after, MaxRows: p.Limit(),
		})
		if err != nil {
			return err
		}
		rows, next = page.Finish(p, rows, func(x dbq.ListPaymentMerchantCapsRow) ids.UUID { return x.ID })
		for _, x := range rows {
			out = append(out, s.of(c.Org, Cap{
				ID: x.ID, Merchant: x.Merchant, Currency: x.Currency, MaxPerPaymentMinor: x.MaxPerPaymentMinor,
				MaxPerDayMinor: x.MaxPerDayMinor, State: x.State, CreatedBy: x.CreatedBy, CreatedAt: x.CreatedAt,
				ApprovedBy: x.ApprovedBy, ActivatedAt: x.ActivatedAt, RetiredAt: x.RetiredAt, RetiredBy: deref(x.RetiredBy),
			}, x.ChangeRequestID))
		}
		return nil
	})
	return out, next, err
}

func (s *Service) get(ctx context.Context, org ids.OrgID, id ids.UUID) (Cap, error) {
	var out Cap
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		x, err := dbq.New(tx).GetPaymentMerchantCap(ctx, org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		out = s.of(org, Cap{
			ID: x.ID, Merchant: x.Merchant, Currency: x.Currency, MaxPerPaymentMinor: x.MaxPerPaymentMinor,
			MaxPerDayMinor: x.MaxPerDayMinor, State: x.State, CreatedBy: x.CreatedBy, CreatedAt: x.CreatedAt,
			ApprovedBy: x.ApprovedBy, ActivatedAt: x.ActivatedAt, RetiredAt: x.RetiredAt, RetiredBy: deref(x.RetiredBy),
		}, x.ChangeRequestID)
		return nil
	})
	return out, err
}

func (s *Service) of(org ids.OrgID, c Cap, req *ids.UUID) Cap {
	if req != nil {
		c.ChangeRequest = *req
		if s.Changes != nil {
			c.ChangeRequestURL = s.Changes.URL(org, *req)
		}
	}
	return c
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// ActiveCap returns the ACTIVE cap of merchant in currency, read in tx (the
// payment step's reader); ok false when there is none.
func ActiveCap(ctx context.Context, tx db.TenantTx, org ids.OrgID, merchant, currency string) (Active, bool, error) {
	x, err := dbq.New(tx).ActivePaymentMerchantCap(ctx, org, merchant, currency)
	if db.IsNoRows(err) {
		return Active{}, false, nil
	}
	if err != nil {
		return Active{}, false, err
	}
	return Active{ID: x.ID, MaxPerPaymentMinor: x.MaxPerPaymentMinor, MaxPerDayMinor: x.MaxPerDayMinor}, true, nil
}
