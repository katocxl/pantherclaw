// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package capture

import (
	"context"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	agents "github.com/katocxl/pantherclaw/internal/agents/app"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Errors of the capture use cases.
var (
	ErrHumanOnly          = pcerr.New(pcerr.PermissionDenied, "HUMAN_ONLY", "only a person can do this")
	ErrProfile            = pcerr.New(pcerr.InvalidArgument, "INVALID_CAPTURE_PROFILE", "a capture profile needs a purpose of 1 to 500 characters, 1 to 32 connections, 1 to 64 operations, the request or the response, a byte cap of 1 to 65536, a retention of 1 to 30 days and an expiry of 1 to 90 days")
	ErrConnection         = pcerr.New(pcerr.NotFound, "CONNECTION_NOT_FOUND", "a connection was not found")
	ErrProfileNotFound    = pcerr.New(pcerr.NotFound, "CAPTURE_PROFILE_NOT_FOUND", "capture profile not found")
	ErrProfileNotActive   = pcerr.New(pcerr.FailedPrecondition, "CAPTURE_PROFILE_NOT_ACTIVE", "the capture profile is no longer active")
	ErrCaptureNotFound    = pcerr.New(pcerr.NotFound, "PAYLOAD_CAPTURE_NOT_FOUND", "no payload capture of that transaction and direction")
	ErrReason             = pcerr.New(pcerr.InvalidArgument, "INVALID_REASON", "a reason of 1 to 500 bytes is required")
	ErrDirection          = pcerr.New(pcerr.InvalidArgument, "INVALID_DIRECTION", "the direction is request or response")
	ErrCaptureUnavailable = pcerr.New(pcerr.Internal, "PAYLOAD_CAPTURE_UNREADABLE", "the payload capture cannot be opened")
)

// Notifier enqueues notifications in the caller's transaction (M5).
type Notifier interface {
	Enqueue(ctx context.Context, tx db.TenantTx, m napp.Message) (napp.Enqueued, error)
}

// Service serves the capture profile use cases and the audited read as
// pc_app.
type Service struct {
	Pool *db.Pool
	// Env opens captures with the org's payload_captures key.
	Env *pccrypto.Envelope
	// Notify tells the org's admins and auditors about profiles; nil sends
	// nothing.
	Notify Notifier
}

// human returns the caller, who must be a person signed in as themselves
// (never an API key or a service account).
func human(ctx context.Context) (tenancy.Caller, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	if !c.Human() || c.Credential == tenancy.CredAPIKey {
		return c, ErrHumanOnly
	}
	return c, nil
}

// manager returns the caller, who must be a person holding
// evidence.capture.manage at org scope.
func manager(ctx context.Context) (tenancy.Caller, error) {
	c, err := human(ctx)
	if err != nil {
		return c, err
	}
	return c, c.Require(td.PermEvidenceCaptureManage, td.OrgPath(c.Org))
}

var operationPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_]+){1,7}$`)

// ProfileRequest creates a capture profile.
type ProfileRequest struct {
	Purpose           string
	Connections       []ids.UUID
	Operations        []string
	Request, Response bool
	ByteCap           int
	RetentionDays     int
	ExpiresInDays     int
}

func (r ProfileRequest) check() error {
	switch {
	case !validText(r.Purpose, MaxPurpose),
		len(r.Connections) < 1 || len(r.Connections) > maxConnections,
		len(r.Operations) < 1 || len(r.Operations) > maxOperations,
		!r.Request && !r.Response,
		r.ByteCap < 1 || r.ByteCap > MaxBytes,
		r.RetentionDays < 1 || r.RetentionDays > MaxRetentionDays,
		r.ExpiresInDays < 1 || r.ExpiresInDays > MaxExpiryDays:
		return ErrProfile
	}
	for _, op := range r.Operations {
		if len(op) > 128 || !operationPattern.MatchString(op) {
			return ErrProfile
		}
	}
	for _, c := range r.Connections {
		if c.IsZero() {
			return ErrProfile
		}
	}
	return nil
}

// Profile states.
const (
	StateActive   = "ACTIVE"
	StateDisabled = "DISABLED"
	StateExpired  = "EXPIRED"
)

// Profile is a capture profile; State reads EXPIRED once it expired.
type Profile struct {
	dbq.PcCaptureProfile
	EffectiveState string
}

func unique[T comparable](s []T) []T {
	out := make([]T, 0, len(s))
	for _, v := range s {
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

// CreateProfile creates a capture profile: audited, notified to the org's
// admins and auditors, and sent to the gateways serving its connections.
func (s *Service) CreateProfile(ctx context.Context, r ProfileRequest) (Profile, error) {
	c, err := manager(ctx)
	if err != nil {
		return Profile{}, err
	}
	r.Connections, r.Operations = unique(r.Connections), unique(r.Operations)
	if err := r.check(); err != nil {
		return Profile{}, err
	}
	var out Profile
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		n, err := q.CountCaptureConnections(ctx, c.Org, r.Connections)
		if err != nil {
			return err
		}
		if int(n) != len(r.Connections) {
			return ErrConnection
		}
		p, err := q.InsertCaptureProfile(ctx, dbq.InsertCaptureProfileParams{
			OrgID: c.Org, ID: ids.NewV7(), Purpose: r.Purpose, Connections: r.Connections, Operations: r.Operations,
			CaptureRequest: r.Request, CaptureResponse: r.Response, ByteCap: int32(r.ByteCap), //nolint:gosec // G115: ≤ 65536
			RetentionDays: int32(r.RetentionDays), ExpiresInDays: int32(r.ExpiresInDays), CreatedBy: c.Principal.ID, //nolint:gosec // G115: ≤ 90
		})
		if err != nil {
			return err
		}
		if err := q.BumpGatewaysOfConnections(ctx, c.Org, r.Connections); err != nil {
			return err
		}
		directions := []string{}
		if r.Request {
			directions = append(directions, string(Request))
		}
		if r.Response {
			directions = append(directions, string(Response))
		}
		expires := p.ExpiresAt.UTC().Format(time.RFC3339)
		if _, err := audit.Record(ctx, tx, audit.Event{
			Name: "evidence.capture_profile_created", Actor: c.Actor(), Outcome: audit.Success,
			Object: &audit.Object{Type: "capture_profile", ID: p.ID.String()},
			Details: map[string]string{
				"connections": strconv.Itoa(len(r.Connections)), "operations": strconv.Itoa(len(r.Operations)),
				"directions": strings.Join(directions, ","), "byte_cap": strconv.Itoa(r.ByteCap),
				"retention_days": strconv.Itoa(r.RetentionDays), "expires": expires,
			},
		}); err != nil {
			return err
		}
		if err := s.tell(ctx, tx, q, c.Org, "evidence.capture_profile_created", map[string]string{
			"profile": p.ID.String(), "connections": strconv.Itoa(len(r.Connections)), "expires": expires,
		}); err != nil {
			return err
		}
		out = Profile{PcCaptureProfile: p, EffectiveState: p.State}
		return nil
	})
	return out, err
}

// DisableProfile disables an active profile at once: audited, notified,
// and the gateways serving its connections stop capturing with their next
// configuration (the server drops captures under it from now on).
func (s *Service) DisableProfile(ctx context.Context, id ids.UUID) (Profile, error) {
	c, err := manager(ctx)
	if err != nil {
		return Profile{}, err
	}
	var out Profile
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if _, err := q.GetCaptureProfile(ctx, c.Org, id); db.IsNoRows(err) {
			return ErrProfileNotFound
		} else if err != nil {
			return err
		}
		by := c.Principal.ID
		p, err := q.DisableCaptureProfile(ctx, &by, c.Org, id)
		if db.IsNoRows(err) {
			return ErrProfileNotActive
		} else if err != nil {
			return err
		}
		if err := q.BumpGatewaysOfConnections(ctx, c.Org, p.Connections); err != nil {
			return err
		}
		if _, err := audit.Record(ctx, tx, audit.Event{
			Name: "evidence.capture_profile_disabled", Actor: c.Actor(), Outcome: audit.Success,
			Object: &audit.Object{Type: "capture_profile", ID: id.String()},
		}); err != nil {
			return err
		}
		if err := s.tell(ctx, tx, q, c.Org, "evidence.capture_profile_disabled", map[string]string{"profile": id.String()}); err != nil {
			return err
		}
		out = Profile{PcCaptureProfile: p, EffectiveState: p.State}
		return nil
	})
	return out, err
}

// tell notifies the org's admins and auditors (HR-199).
func (s *Service) tell(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, typ string, params map[string]string) error {
	if s.Notify == nil {
		return nil
	}
	people, err := q.OrgUsersWithRoles(ctx, org, []string{string(td.RoleOrgAdmin), string(td.RoleAuditor)})
	if err != nil {
		return err
	}
	_, err = s.Notify.Enqueue(ctx, tx, napp.Message{Org: org, Type: typ, Params: params, Personal: people})
	return err
}

// ProfilePage is one page of profiles, newest first.
type ProfilePage struct {
	Items []Profile
	Next  string
}

// ListProfiles lists the org's capture profiles, newest first, optionally
// in one state.
func (s *Service) ListProfiles(ctx context.Context, state string, size int32, token string) (ProfilePage, error) {
	c, err := manager(ctx)
	if err != nil {
		return ProfilePage{}, err
	}
	pr, err := page.Parse(size, token)
	if err != nil {
		return ProfilePage{}, err
	}
	var before *ids.UUID
	if !pr.After.IsZero() {
		before = &pr.After
	}
	var st *string
	if state != "" {
		st = &state
	}
	var out ProfilePage
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListCaptureProfilesPage(ctx, dbq.ListCaptureProfilesPageParams{
			OrgID: c.Org, State: st, Before: before, MaxRows: pr.Limit(),
		})
		if err != nil {
			return err
		}
		rows, out.Next = page.Finish(pr, rows, func(r dbq.ListCaptureProfilesPageRow) ids.UUID { return r.ID })
		for _, r := range rows {
			out.Items = append(out.Items, Profile{PcCaptureProfile: dbq.PcCaptureProfile{
				OrgID: r.OrgID, ID: r.ID, Purpose: r.Purpose, Connections: r.Connections, Operations: r.Operations,
				CaptureRequest: r.CaptureRequest, CaptureResponse: r.CaptureResponse, ByteCap: r.ByteCap,
				RetentionDays: r.RetentionDays, ExpiresAt: r.ExpiresAt, State: r.State, CreatedBy: r.CreatedBy,
				CreatedAt: r.CreatedAt, DisabledBy: r.DisabledBy, DisabledAt: r.DisabledAt,
			}, EffectiveState: r.EffectiveState})
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// Read is an opened capture.
type Read struct {
	ID, Attempt, Transaction, Profile ids.UUID
	Direction                         Direction
	Size                              int
	Truncated                         bool
	Created, RemoveAt                 time.Time
	Content                           []byte
}

// ReadCapture opens the capture of txn's dispatch in direction for a
// person holding evidence.read_restricted where the transaction's agent
// lives, with a reason. The read (who, which capture, the reason) is
// written to the audit ledger and committed before the content is opened
// and returned (HR-199).
func (s *Service) ReadCapture(ctx context.Context, txn ids.UUID, dir Direction, reason string) (Read, error) {
	c, err := human(ctx)
	if err != nil {
		return Read{}, err
	}
	if !c.CanAnywhere(td.PermEvidenceReadRestricted) {
		return Read{}, td.ErrPermissionDenied(td.PermEvidenceReadRestricted)
	}
	if dir != Request && dir != Response {
		return Read{}, ErrDirection
	}
	if s.Env == nil {
		return Read{}, ErrCaptureUnavailable
	}
	if reason == "" || len(reason) > MaxReason || !validText(reason, MaxReason) {
		return Read{}, ErrReason
	}
	var row dbq.GetPayloadCaptureRow
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		row, err = q.GetPayloadCapture(ctx, c.Org, txn, string(dir))
		if db.IsNoRows(err) {
			return ErrCaptureNotFound
		} else if err != nil {
			return err
		}
		a, err := q.GetAgent(ctx, c.Org, row.AgentID)
		if err != nil {
			return err
		}
		path, err := agents.PathOf(ctx, q, a)
		if err != nil {
			return err
		}
		if err := c.Require(td.PermEvidenceReadRestricted, path); err != nil {
			return err
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: "evidence.payload_read", Actor: c.Actor(), Outcome: audit.Success,
			Object:  &audit.Object{Type: "payload_capture", ID: row.ID.String()},
			Details: map[string]string{"transaction": txn.String(), "direction": string(dir), "reason": reason},
		})
		return err
	})
	if err != nil {
		return Read{}, err
	}
	content, err := s.Env.Decrypt(ctx, field(c.Org, row.ID), Purpose, row.Content)
	if err != nil {
		return Read{}, ErrCaptureUnavailable
	}
	return Read{
		ID: row.ID, Attempt: row.AttemptID, Transaction: row.TransactionID, Profile: row.ProfileID, Direction: Direction(row.Direction),
		Size: int(row.Size), Truncated: row.Truncated, Created: row.CreatedAt, RemoveAt: row.RemoveAt, Content: content,
	}, nil
}
