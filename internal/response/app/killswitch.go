// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app holds the response use cases of M6: the asymmetric org kill
// switch (G0 M6 design decision 5, HR-002, HR-113). One person holding
// containment.killswitch, whose browser session stepped up with a security
// key less than 5 minutes ago, engages it. Restoring needs a proposal and a
// confirmation by a second person with a different security key, each with
// a fresh step-up. Engaging and restoring each raise the containment epoch
// in the same transaction, so every outstanding permit fails BeginDispatch
// and gateways stop within a second (HR-010). Nothing else is undone or
// changed, so restoring brings back exactly what was there.
//
// Only the emergency-stop page calls Engage and the restore use cases;
// ContainmentService and pclaw only read.
package app

import (
	"context"
	"strconv"
	"time"
	"unicode/utf8"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	autoports "github.com/katocxl/pantherclaw/internal/automations/ports"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Timing and limits (G0 M6 design decision 5).
const (
	// StepUpWithin is how fresh the step-up behind an engage, a proposal or
	// a confirmation must be, by the database clock.
	StepUpWithin = 5 * time.Minute
	// RestoreWindow is how long a restore proposal waits for its
	// confirmation.
	RestoreWindow = 30 * time.Minute
	// MaxReason caps the reason, which is stored and shown as untrusted text.
	MaxReason = 500
)

// PagePath is the emergency-stop page.
const PagePath = "/containment"

// Errors.
var (
	ErrStepUp          = pcerr.New(pcerr.PermissionDenied, "STEP_UP_REQUIRED", "a step-up with a security key less than 5 minutes old is required")
	ErrAlreadyEngaged  = pcerr.New(pcerr.FailedPrecondition, "KILL_SWITCH_ENGAGED", "the kill switch is already engaged")
	ErrNotEngaged      = pcerr.New(pcerr.FailedPrecondition, "KILL_SWITCH_NOT_ENGAGED", "the kill switch is not engaged")
	ErrRestorePending  = pcerr.New(pcerr.FailedPrecondition, "RESTORE_PENDING", "a restore is already waiting for confirmation")
	ErrRestoreGone     = pcerr.New(pcerr.FailedPrecondition, "RESTORE_GONE", "the restore proposal was confirmed, canceled or has expired")
	ErrRestoreNotFound = pcerr.New(pcerr.NotFound, "RESTORE_NOT_FOUND", "restore proposal not found")
	ErrSamePerson      = pcerr.New(pcerr.PermissionDenied, "SAME_PERSON", "a second person must confirm a restore")
	ErrSameKey         = pcerr.New(pcerr.PermissionDenied, "SAME_KEY", "the confirmation needs a different security key from the proposal's")
	ErrReason          = pcerr.New(pcerr.InvalidArgument, "REASON_REQUIRED", "a reason of 1 to 500 characters is required")
)

// Notifier queues a notification in the caller's transaction (M5).
type Notifier interface {
	Enqueue(ctx context.Context, tx db.TenantTx, m napp.Message) (napp.Enqueued, error)
}

// Service serves the kill switch.
type Service struct {
	pool      *db.Pool
	notify    Notifier
	publicURL string
	// pauser pauses every automation when the kill switch engages (G0 M11
	// part 2 D14, HR-283); nil while automations are not wired.
	pauser autoports.Pauser
}

// New returns the kill-switch use cases. publicURL is the server's public
// URL, for the page link; n may be nil (no notifications).
func New(pool *db.Pool, n Notifier, publicURL string) *Service {
	return &Service{pool: pool, notify: n, publicURL: publicURL}
}

// StepUp is the proof behind a page action: the person's browser session
// stepped up with this security key at this time (M5 part 1).
type StepUp struct {
	Credential ids.UUID
	At         time.Time
}

// Restore is a pending restore proposal.
type Restore struct {
	ID         ids.UUID
	ProposedBy ids.UUID
	Reason     string
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

// State is the org's kill switch.
type State struct {
	Engaged   bool
	Epoch     int64
	EngagedBy string
	EngagedAt *time.Time
	Reason    string
	Pending   *Restore
	// PageURL is the emergency-stop page for this org.
	PageURL string
}

// PageURL returns the emergency-stop page of org.
func (s *Service) PageURL(org ids.OrgID) string {
	return s.publicURL + PagePath + "?org=" + org.String()
}

// Status returns the org's kill switch (containment.read).
func (s *Service) Status(ctx context.Context) (State, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return State{}, err
	}
	if err := c.Require(td.PermContainmentRead, td.OrgPath(c.Org)); err != nil {
		return State{}, err
	}
	var out State
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, _, err = s.state(ctx, dbq.New(tx), c.Org)
		return err
	})
	return out, err
}

// state reads the kill switch and returns it with the database clock.
func (s *Service) state(ctx context.Context, q *dbq.Queries, org ids.OrgID) (State, time.Time, error) {
	if err := q.InsertContainment(ctx, org); err != nil {
		return State{}, time.Time{}, err
	}
	k, err := q.GetKillSwitch(ctx, org)
	if err != nil {
		return State{}, time.Time{}, err
	}
	out := State{Engaged: k.KillSwitch, Epoch: k.Epoch, EngagedAt: k.EngagedAt, PageURL: s.PageURL(org)}
	if k.EngagedBy != nil {
		out.EngagedBy = *k.EngagedBy
	}
	if k.EngageReason != nil {
		out.Reason = *k.EngageReason
	}
	switch r, err := q.PendingRestore(ctx, org); {
	case err == nil:
		out.Pending = &Restore{ID: r.ID, ProposedBy: r.ProposedBy, Reason: r.Reason, CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt}
	case !db.IsNoRows(err):
		return State{}, time.Time{}, err
	}
	return out, k.Now, nil
}

// person checks that the caller may change the kill switch: a person
// holding containment.killswitch (human only) whose step-up, with one of
// their own active security keys, is fresh by the database clock.
func person(ctx context.Context, q *dbq.Queries, c tenancy.Caller, su StepUp, now time.Time) error {
	if err := c.Require(td.PermContainmentKillSwitch, td.OrgPath(c.Org)); err != nil {
		return err
	}
	if !c.Human() || su.Credential.IsZero() || su.At.IsZero() || now.Sub(su.At) > StepUpWithin || su.At.After(now.Add(time.Minute)) {
		return ErrStepUp
	}
	k, err := q.CredentialOfUser(ctx, c.Org, su.Credential, c.Principal.ID)
	if db.IsNoRows(err) {
		return ErrStepUp
	} else if err != nil {
		return err
	}
	if k.State != "ACTIVE" {
		return ErrStepUp
	}
	return nil
}

func reasonOK(r string) bool {
	n := utf8.RuneCountInString(r)
	return utf8.ValidString(r) && n >= 1 && n <= MaxReason
}

// withReason adds the reason to audit details, cut at a rune boundary to
// the ledger's 512-byte detail limit (reason_truncated says so).
func withReason(d map[string]string, reason string) map[string]string {
	const limit = 512
	if len(reason) > limit {
		cut := limit
		for cut > 0 && !utf8.RuneStart(reason[cut]) {
			cut--
		}
		reason = reason[:cut]
		d["reason_truncated"] = "true"
	}
	d["reason"] = reason
	return d
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func (s *Service) notifyOrg(ctx context.Context, tx db.TenantTx, c tenancy.Caller, typ string) error {
	if s.notify == nil {
		return nil
	}
	_, err := s.notify.Enqueue(ctx, tx, napp.Message{Org: c.Org, Type: typ, Params: map[string]string{"user": c.Principal.String()}})
	return err
}

func record(ctx context.Context, tx db.TenantTx, c tenancy.Caller, name string, details map[string]string) error {
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: c.Actor(), Outcome: audit.Success, Object: &audit.Object{Type: "org", ID: c.Org.String()}, Details: details,
	})
	return err
}

// Engage engages the kill switch. In one transaction it sets the switch,
// raises the epoch (the row's trigger sends NOTIFY), records who, when and
// why, writes security.kill_switch_engaged and notifies the org. The record
// states what else the kill switch did for the org's connections: nothing
// is revoked at a provider in M6; every active automation is paused
// (KILL_SWITCH) and its executions are canceled by the engine at their
// next boundary.
func (s *Service) Engage(ctx context.Context, su StepUp, reason string) (State, error) {
	if !reasonOK(reason) {
		return State{}, ErrReason
	}
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return State{}, err
	}
	var out State
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		st, now, err := s.state(ctx, q, c.Org)
		if err != nil {
			return err
		}
		if err := person(ctx, q, c, su, now); err != nil {
			return err
		}
		if st.Engaged {
			return ErrAlreadyEngaged
		}
		r, err := q.EngageKillSwitch(ctx, c.Principal.String(), reason, c.Org)
		if db.IsNoRows(err) {
			return ErrAlreadyEngaged
		} else if err != nil {
			return err
		}
		conns, err := q.CountLiveConnections(ctx, c.Org)
		if err != nil {
			return err
		}
		paused := "none_exist"
		if s.pauser != nil {
			pausedIDs, err := s.pauser.Pause(ctx, tx.Pgx(), c.Org, autodomain.PauseSelector{All: true}, autodomain.PauseKillSwitch)
			if err != nil {
				return err
			}
			paused = itoa(int64(len(pausedIDs)))
		}
		if err := record(ctx, tx, c, "security.kill_switch_engaged", withReason(map[string]string{
			"epoch": itoa(r.Epoch), "key_id": su.Credential.String(), "connections": itoa(conns),
			"provider_revocation": "not_supported", "automations_paused": paused,
		}, reason)); err != nil {
			return err
		}
		if err := s.notifyOrg(ctx, tx, c, "security.kill_switch_engaged"); err != nil {
			return err
		}
		out, _, err = s.state(ctx, q, c.Org)
		return err
	})
	return out, err
}

// WithPauser pauses every automation of the org in the transaction that
// engages the kill switch (G0 M11 part 2 D14, HR-283). Restore resumes
// none of them.
func (s *Service) WithPauser(p autoports.Pauser) *Service {
	s.pauser = p
	return s
}
