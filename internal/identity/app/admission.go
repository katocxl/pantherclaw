// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json/v2"
	"time"

	agents "github.com/katocxl/pantherclaw/internal/agents/app"
	adomain "github.com/katocxl/pantherclaw/internal/agents/domain"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Instance is one workload key of an agent with its verification metadata
// (F031).
type Instance struct {
	ID            ids.UUID
	AgentID       ids.UUID
	Identifier    pap.Instance
	Thumbprint    string
	State         string
	EnrolledVia   string
	Level         int
	AttestedUntil *time.Time
	ReleaseState  string
	ReleaseDigest string
	NeedsReview   bool
	Binding       map[string]string
	LastNetwork   string
	LastSeenAt    *time.Time
	DecidedBy     string
	DecidedAt     *time.Time
	RevokeReason  string
	CreatedAt     time.Time
	ExpiresAt     *time.Time
}

func instanceView(r dbq.PcAgentInstance) Instance {
	in := Instance{
		ID: r.ID, AgentID: r.AgentID, Identifier: pap.Instance{Org: r.OrgID, Agent: r.AgentID, Instance: r.ID},
		Thumbprint: r.Jkt, State: r.State, EnrolledVia: r.EnrolledVia, Level: int(r.AttLevel), AttestedUntil: r.AttestedUntil,
		NeedsReview: r.NeedsReview, LastSeenAt: r.LastSeenAt, DecidedAt: r.DecidedAt, CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt,
	}
	for dst, src := range map[*string]*string{
		&in.ReleaseState: r.ReleaseState, &in.ReleaseDigest: r.ReleaseDigest, &in.LastNetwork: r.LastNetwork,
		&in.DecidedBy: r.DecidedBy, &in.RevokeReason: r.RevokeReason,
	} {
		if src != nil {
			*dst = *src
		}
	}
	if len(r.Binding) > 0 {
		_ = json.Unmarshal(r.Binding, &in.Binding)
	}
	return in
}

// loadInstance reads an instance and its agent and checks p where the
// agent lives; another org's id is NotFound.
func loadInstance(ctx context.Context, c tenancy.Caller, q *dbq.Queries, id ids.UUID, p td.Permission) (dbq.PcAgentInstance, dbq.PcAgent, error) {
	in, err := q.LockInstance(ctx, c.Org, id)
	if db.IsNoRows(err) {
		return in, dbq.PcAgent{}, ErrInstanceNotFound
	} else if err != nil {
		return in, dbq.PcAgent{}, err
	}
	a, err := q.LockAgent(ctx, c.Org, in.AgentID)
	if err != nil {
		return in, a, err
	}
	path, err := agents.PathOf(ctx, q, a)
	if err != nil {
		return in, a, err
	}
	return in, a, c.Require(p, path)
}

// GetInstance returns one instance.
func (s *Service) GetInstance(ctx context.Context, id ids.UUID) (Instance, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Instance{}, err
	}
	var out Instance
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		in, _, err := loadInstance(ctx, c, dbq.New(tx), id, td.PermAgentRead)
		out = instanceView(in)
		return err
	})
	return out, err
}

// ListInstances pages through an agent's instances.
func (s *Service) ListInstances(ctx context.Context, agentID ids.UUID, pr page.Request, states []string) ([]Instance, string, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return nil, "", err
	}
	var out []Instance
	var next string
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		a, err := q.GetAgent(ctx, c.Org, agentID)
		if db.IsNoRows(err) {
			return ErrAgentNotFound
		} else if err != nil {
			return err
		}
		path, err := agents.PathOf(ctx, q, a)
		if err != nil {
			return err
		}
		if err := c.Require(td.PermAgentRead, path); err != nil {
			return err
		}
		if states == nil {
			states = []string{}
		}
		rows, err := q.ListInstances(ctx, dbq.ListInstancesParams{OrgID: c.Org, AgentID: agentID, After: pr.After, States: states, PageLimit: pr.Limit()})
		if err != nil {
			return err
		}
		rows, next = page.Finish(pr, rows, func(r dbq.PcAgentInstance) ids.UUID { return r.ID })
		for _, r := range rows {
			out = append(out, instanceView(r))
		}
		return nil
	}, db.ReadOnly())
	return out, next, err
}

// Admit admits a pending instance (HR-094). The caller must be a person
// holding agent.admit where the agent lives and must be the agent's owner
// or backup owner, and must give the full fingerprint the workload
// displayed. Admission resolves the instance's ADMISSION entry and moves a
// claimed agent to VERIFIED.
func (s *Service) Admit(ctx context.Context, id ids.UUID, fingerprint string) (Instance, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Instance{}, err
	}
	if !c.Human() {
		return Instance{}, td.ErrPermissionDenied(td.PermAgentAdmit)
	}
	var out Instance
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		in, a, err := loadInstance(ctx, c, q, id, td.PermAgentAdmit)
		if err != nil {
			return err
		}
		if !isOwner(c, a) {
			return ErrNotOwner
		}
		if !agentUsable(a) {
			return ErrAgentUnusable
		}
		if subtle.ConstantTimeCompare([]byte(fingerprint), []byte(in.Jkt)) != 1 {
			return ErrFingerprint
		}
		by := c.Principal.String()
		r, err := q.AdmitInstance(ctx, &by, c.Org, in.ID)
		if db.IsNoRows(err) {
			return ErrInstanceGone
		} else if err != nil {
			return err
		}
		if _, err := q.CloseSubjectEntry(ctx, dbq.CloseSubjectEntryParams{
			OrgID: c.Org, SubjectType: "instance", SubjectID: in.ID, State: "APPROVED", DecidedBy: &by, Reason: "fingerprint confirmed",
		}); err != nil {
			return err
		}
		actor := ownerActor(c)
		if err := agents.MarkVerified(ctx, q, c.Org, a.ID, actor); err != nil {
			return err
		}
		if err := agents.RecordChange(ctx, q, c.Org, a.ID, adomain.Change{
			Kind: adomain.ChangeInstanceAdmitted, Actor: actor, Details: map[string]string{"instance_id": in.ID.String()},
		}); err != nil {
			return err
		}
		out = instanceView(r)
		return callerRecord(ctx, tx, c, auditkind.IdentityInstanceAdmitted, in.ID, map[string]string{"agent_id": a.ID.String()})
	})
	return out, err
}

func ownerActor(c tenancy.Caller) adomain.Actor {
	if c.Principal.Kind == td.KindServiceAccount {
		return adomain.ServiceAccountActor(c.Principal.ID)
	}
	return adomain.UserActor(c.Principal.ID)
}

// Reject rejects a pending instance, with the same requirements as Admit.
func (s *Service) Reject(ctx context.Context, id ids.UUID, reason string) (Instance, error) {
	if err := adomain.ValidateReason(reason); err != nil {
		return Instance{}, pcerr.Wrap(err, pcerr.InvalidArgument, "REASON", err.Error())
	}
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Instance{}, err
	}
	if !c.Human() {
		return Instance{}, td.ErrPermissionDenied(td.PermAgentAdmit)
	}
	var out Instance
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		in, a, err := loadInstance(ctx, c, q, id, td.PermAgentAdmit)
		if err != nil {
			return err
		}
		if !isOwner(c, a) {
			return ErrNotOwner
		}
		out, err = s.close(ctx, q, tx, c, in, a, "PENDING_ADMISSION", "REJECTED", "REJECTED", reason, adomain.ChangeInstanceRejected)
		return err
	})
	return out, err
}

// Revoke revokes an instance: no new workload tokens, its requests are
// refused, and the containment epoch moves so outstanding permits fail
// (HR-002).
func (s *Service) Revoke(ctx context.Context, id ids.UUID, reason string) (Instance, error) {
	if err := adomain.ValidateReason(reason); err != nil {
		return Instance{}, pcerr.Wrap(err, pcerr.InvalidArgument, "REASON", err.Error())
	}
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return Instance{}, err
	}
	var out Instance
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		in, a, err := loadInstance(ctx, c, q, id, td.PermAgentManage)
		if err != nil {
			return err
		}
		if in.State != "ADMITTED" && in.State != "PENDING_ADMISSION" {
			return ErrInstanceGone
		}
		if out, err = s.close(ctx, q, tx, c, in, a, in.State, "REVOKED", "CANCELLED", reason, adomain.ChangeInstanceRevoked); err != nil { //nolint:misspell // stored value
			return err
		}
		if err := q.InsertContainment(ctx, c.Org); err != nil {
			return err
		}
		_, err = q.BumpEpoch(ctx, c.Org)
		return err
	})
	return out, err
}

func (s *Service) close(ctx context.Context, q *dbq.Queries, tx db.TenantTx, c tenancy.Caller, in dbq.PcAgentInstance,
	a dbq.PcAgent, from, to, entryState, reason string, kind adomain.ChangeKind,
) (Instance, error) {
	by := c.Principal.String()
	r, err := q.CloseInstance(ctx, dbq.CloseInstanceParams{
		OrgID: c.Org, ID: in.ID, FromState: from, ToState: to, DecidedBy: &by, Reason: &reason,
	})
	if db.IsNoRows(err) {
		return Instance{}, ErrInstanceGone
	} else if err != nil {
		return Instance{}, err
	}
	if _, err := q.CloseSubjectEntry(ctx, dbq.CloseSubjectEntryParams{
		OrgID: c.Org, SubjectType: "instance", SubjectID: in.ID, State: entryState, DecidedBy: &by, Reason: reason,
	}); err != nil {
		return Instance{}, err
	}
	if err := agents.RecordChange(ctx, q, c.Org, a.ID, adomain.Change{
		Kind: kind, Actor: ownerActor(c), Reason: reason, Details: map[string]string{"instance_id": in.ID.String()},
	}); err != nil {
		return Instance{}, err
	}
	return instanceView(r), callerRecord(ctx, tx, c, instanceClosedKinds[to], in.ID, map[string]string{"agent_id": a.ID.String()})
}

// instanceClosedKinds are the audit kinds of an instance's closing states
// (HR-664).
var instanceClosedKinds = map[string]string{
	"REJECTED": auditkind.IdentityInstanceRejected, "REVOKED": auditkind.IdentityInstanceRevoked,
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func ptr[T any](v T) *T { return &v }

func optString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func evdomainSystem() evdomain.Actor { return evdomain.Actor{Type: "system", ID: "identity"} }
