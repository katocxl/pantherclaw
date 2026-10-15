// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	"github.com/katocxl/pantherclaw/internal/response/adapters/pgresponse"
	rdomain "github.com/katocxl/pantherclaw/internal/response/domain"
)

// Errors of credential changes (D25).
var (
	ErrCredentialNotFound = pcerr.New(pcerr.NotFound, "CREDENTIAL_NOT_FOUND", "no such credential version of the connection")
	ErrCredentialPreview  = pcerr.New(pcerr.FailedPrecondition, "PREVIEW_STALE",
		"a credential change first discloses every workload sharing the credential: preview it and confirm the preview's digest, which no longer matches")
	ErrSealFirst = pcerr.New(pcerr.FailedPrecondition, "SEAL_NEW_VALUE",
		"rotating a static credential needs a new value sealed for the connection first (credential.seal); this version is still the active one")
	ErrAttestation = pcerr.New(pcerr.InvalidArgument, "ATTESTATION_INVALID",
		"attesting a revocation at the provider needs a security-key step-up and a note of 1 to 500 characters")
	ErrAttestationRequired = pcerr.New(pcerr.FailedPrecondition, "ATTESTATION_REQUIRED",
		"the agent holds this credential: PantherClaw can only record your attestation that it was revoked at the provider")
	ErrCredentialRevoked = pcerr.New(pcerr.FailedPrecondition, "CREDENTIAL_REVOKED", "the credential version is already revoked")
)

// Credential kinds (credentials/domain).
const (
	credentialStatic    = "static"
	credentialGitHubApp = "github_app" //nolint:gosec // G101: a credential kind, not a credential
	// credentialAgentHeld is the credential an agent holds itself (version 0 of
	// an agent_held connection): PantherClaw has no copy.
	credentialAgentHeld = "agent_held"
)

// installationTokenLife is how long a GitHub App installation token minted
// before a rotation stays valid at GitHub.
const installationTokenLife = time.Hour

// CredentialPreview is every workload sharing a sealed credential (D25,
// F555, HR-252): the agents with a route through its connection (or every
// agent, when a route serves them all), their active runs, the other
// connections sharing its GitHub App installation, and the gateway that
// holds it. Digest covers all of it.
type CredentialPreview struct {
	Connection ids.UUID   `json:"connection"`
	Version    int32      `json:"version"`
	Kind       string     `json:"kind"`
	State      string     `json:"state"`
	Gateway    ids.UUID   `json:"gateway"`
	Agents     []ids.UUID `json:"agents"`
	EveryAgent bool       `json:"every_agent,omitzero"`
	Runs       []ids.UUID `json:"runs"`
	RunsOver   bool       `json:"runs_over,omitzero"`
	Shared     []ids.UUID `json:"shared_connections"`
	Unknown    []string   `json:"unknown"`
	Digest     []byte     `json:"-"`
}

// PreviewCredentialIn lists who shares a sealed credential, in tx; version
// 0 names the credential an agent holds itself on an agent_held connection.
func (s *Containment) PreviewCredentialIn(ctx context.Context, tx db.TenantTx, connection ids.UUID, version int32) (CredentialPreview, error) {
	org := tx.OrgID()
	q := dbq.New(tx)
	p := CredentialPreview{
		Connection: connection, Version: version, Agents: []ids.UUID{}, Runs: []ids.UUID{}, Shared: []ids.UUID{}, Unknown: []string{},
	}
	if version == 0 {
		// Version 0 is the credential an agent holds itself (D61).
		c, err := q.ConnectionAccess(ctx, org, connection)
		if db.IsNoRows(err) || (err == nil && c.AccessMode != credentialAgentHeld) {
			return CredentialPreview{}, ErrCredentialNotFound
		} else if err != nil {
			return CredentialPreview{}, err
		}
		p.Kind, p.State, p.Gateway = credentialAgentHeld, "AGENT_HELD", c.GatewayID
		p.Unknown = append(p.Unknown, "the agent holds this credential; PantherClaw has no copy and cannot revoke it")
	} else {
		c, err := q.CredentialOfConnection(ctx, org, connection, version)
		if db.IsNoRows(err) {
			return CredentialPreview{}, ErrCredentialNotFound
		} else if err != nil {
			return CredentialPreview{}, err
		}
		p.Kind, p.State, p.Gateway = c.Kind, c.State, c.GatewayID
	}
	agents, err := q.CredentialAgents(ctx, org, connection)
	if err != nil {
		return CredentialPreview{}, err
	}
	for _, a := range agents {
		if a != nil {
			p.Agents = append(p.Agents, *a)
		}
	}
	every, err := q.CredentialEveryAgentRoutes(ctx, org, connection)
	if err != nil {
		return CredentialPreview{}, err
	}
	if p.EveryAgent = every > 0; p.EveryAgent {
		p.Unknown = append(p.Unknown, "a route of the connection serves every agent, so any agent may depend on the credential")
	}
	runs, err := q.ScopeActiveRuns(ctx, org, rdomain.ScopeConnection, connection.String())
	if err != nil {
		return CredentialPreview{}, err
	}
	if len(runs) > maxPreviewRuns {
		runs, p.RunsOver = runs[:maxPreviewRuns], true
	}
	for _, r := range runs {
		p.Runs = append(p.Runs, r.ID)
	}
	if p.Shared, err = q.SharedInstallationConnections(ctx, org, connection); err != nil {
		return CredentialPreview{}, err
	}
	if p.Shared == nil {
		p.Shared = []ids.UUID{}
	}
	b, err := json.Marshal(p, json.Deterministic(true))
	if err != nil {
		return CredentialPreview{}, err
	}
	p.Digest = sha(b)
	return p, nil
}

// CredentialChange is a revoke or rotate request (D25).
type CredentialChange struct {
	Connection ids.UUID
	Version    int32
	Reason     string
	// PreviewDigest must be the digest of the credential's current preview
	// (HR-252): every sharing workload was disclosed first.
	PreviewDigest []byte
	CaseID        *ids.UUID
	IncidentID    *ids.UUID
	Actor         reflexdomain.Subject
	// Attested: the person attests, at a security-key step-up the service
	// checked at AttestedAt, that the credential was revoked at its
	// provider, saying how (D61). Only that closes upstream exposure.
	Attested    bool
	Attestation string
	AttestedAt  time.Time
}

// RevokeCredentialIn revokes one version of a connection's sealed
// credential through the existing revoke path (the version is REVOKED, the
// epoch and the gateway's configuration are raised, connection.sealed_revoked
// is audited), as a REVOKE response action whose gateway path confirms once
// the gateway is sent the new epoch.
func (s *Containment) RevokeCredentialIn(ctx context.Context, tx db.TenantTx, r CredentialChange) (reflexdomain.ContainResult, error) {
	return s.changeCredential(ctx, tx, r, rdomain.KindRevoke)
}

// RotateCredentialIn rotates a connection's credential (D25). A static one
// must already have a new value sealed (credential.seal), which superseded
// this version; a github_app one makes the gateway mint fresh installation
// tokens: its configuration and the epoch are raised, so tokens minted
// before are not used again. Both are ROTATE response actions.
func (s *Containment) RotateCredentialIn(ctx context.Context, tx db.TenantTx, r CredentialChange) (reflexdomain.ContainResult, error) {
	return s.changeCredential(ctx, tx, r, rdomain.KindRotate)
}

func (s *Containment) changeCredential(ctx context.Context, tx db.TenantTx, r CredentialChange, kind string) (reflexdomain.ContainResult, error) {
	org := tx.OrgID()
	q := dbq.New(tx)
	actor, source, evActor, err := actorOf(r.Actor)
	if err != nil {
		return reflexdomain.ContainResult{}, err
	}
	if !reasonOK1000(r.Reason) {
		return reflexdomain.ContainResult{}, rdomain.ErrReason
	}
	if r.Attested && (r.AttestedAt.IsZero() || !reasonOK(r.Attestation)) {
		return reflexdomain.ContainResult{}, ErrAttestation
	}
	if _, err := q.LockConnection(ctx, org, r.Connection); db.IsNoRows(err) {
		return reflexdomain.ContainResult{}, ErrCredentialNotFound
	} else if err != nil {
		return reflexdomain.ContainResult{}, err
	}
	p, err := s.PreviewCredentialIn(ctx, tx, r.Connection, r.Version)
	if err != nil {
		return reflexdomain.ContainResult{}, err
	}
	if !bytes.Equal(r.PreviewDigest, p.Digest) {
		return reflexdomain.ContainResult{}, ErrCredentialPreview
	}
	if p.State == "REVOKED" {
		return reflexdomain.ContainResult{}, ErrCredentialRevoked
	}
	details := map[string]string{"connection": r.Connection.String(), "version": strconv.Itoa(int(r.Version)), "kind": p.Kind}
	credentialPath := map[string]string{"connection": r.Connection.String()}
	status := rdomain.PathUnresolved
	var until time.Time
	switch {
	case p.Kind == credentialAgentHeld:
		// The agent holds it: PantherClaw changes nothing, and only the
		// person's attestation that it was revoked at the provider counts.
		if !r.Attested {
			return reflexdomain.ContainResult{}, ErrAttestationRequired
		}
	case kind == rdomain.KindRevoke:
		by := actor
		n, err := q.RevokeCredentialVersion(ctx, dbq.RevokeCredentialVersionParams{RevokedBy: &by, OrgID: org, ConnectionID: r.Connection, Version: r.Version})
		if err != nil {
			return reflexdomain.ContainResult{}, err
		}
		if n == 0 {
			return reflexdomain.ContainResult{}, ErrCredentialRevoked
		}
	case p.Kind == credentialGitHubApp:
		// The gateway mints fresh installation tokens once sent the new
		// epoch; those minted before stay valid at GitHub for up to an hour
		// (D61), so the path waits for both.
		now, err := q.DBNow(ctx)
		if err != nil {
			return reflexdomain.ContainResult{}, err
		}
		until = now.Add(installationTokenLife).UTC().Truncate(time.Second)
		credentialPath["gateway"], credentialPath["tokens_valid_until"] = p.Gateway.String(), until.Format(time.RFC3339)
		status = rdomain.PathPending
	default:
		if p.State == "ACTIVE" {
			return reflexdomain.ContainResult{}, ErrSealFirst
		}
		if _, err := q.ActiveCredentialVersion(ctx, org, r.Connection); db.IsNoRows(err) {
			return reflexdomain.ContainResult{}, ErrSealFirst
		} else if err != nil {
			return reflexdomain.ContainResult{}, err
		}
	}
	if status == rdomain.PathUnresolved {
		// D61: PantherClaw's copy changed here; the upstream secret is closed
		// only by the person's attestation.
		if r.Attested {
			status, credentialPath["upstream"] = rdomain.PathConfirmed, "attested"
		} else {
			credentialPath["note"] = "PantherClaw copy revoked; upstream not attested"
		}
	}
	if err := q.InsertContainment(ctx, org); err != nil {
		return reflexdomain.ContainResult{}, err
	}
	epoch, err := q.BumpEpoch(ctx, org)
	if err != nil {
		return reflexdomain.ContainResult{}, err
	}
	if _, err := q.BumpGatewayConfig(ctx, org, p.Gateway); err != nil {
		return reflexdomain.ContainResult{}, err
	}
	a := pgresponse.Action{
		ID: ids.NewV7(), Kind: kind, ScopeType: "credential", ScopeID: r.Connection.String() + ":" + strconv.Itoa(int(r.Version)),
		Reason: r.Reason, CaseID: r.CaseID, IncidentID: r.IncidentID, Actor: actor, Source: source, PreviewDigest: p.Digest,
	}
	if _, err := pgresponse.InsertAction(ctx, tx, org, a); err != nil {
		return reflexdomain.ContainResult{}, err
	}
	if err := q.SetResponseActionEpoch(ctx, pgtype.Int8{Int64: epoch, Valid: true}, org, a.ID); err != nil {
		return reflexdomain.ContainResult{}, err
	}
	if r.Attested {
		if err := q.AttestResponseAction(ctx, dbq.AttestResponseActionParams{
			OrgID: org, ID: a.ID, AttestedBy: &actor, Attestation: &r.Attestation,
		}); err != nil {
			return reflexdomain.ContainResult{}, err
		}
		details["upstream_attested"] = "true"
	}
	gw := Preview{Gateways: []ids.UUID{p.Gateway}}
	if err := planPaths(ctx, tx, a.ID, kind, gw, epoch); err != nil {
		return reflexdomain.ContainResult{}, err
	}
	if err := addPath(ctx, q, org, a.ID, rdomain.PathCredential, "connection", r.Connection.String(), true, p.Kind, status, credentialPath); err != nil {
		return reflexdomain.ContainResult{}, err
	}
	st, err := s.settle(ctx, tx, org, a.ID)
	if err != nil {
		return reflexdomain.ContainResult{}, err
	}
	details["action"], details["epoch"], details["sharing_agents"] = a.ID.String(), strconv.FormatInt(epoch, 10), strconv.Itoa(len(p.Agents))
	details["shared_connections"] = strconv.Itoa(len(p.Shared))
	name := "response.credential_revoked"
	if kind == rdomain.KindRotate {
		name = "response.credential_rotated"
	}
	if err := recordAction(ctx, tx, evActor, name, a.ID, details, r.Reason); err != nil {
		return reflexdomain.ContainResult{}, err
	}
	if kind == rdomain.KindRevoke && p.Kind != credentialAgentHeld {
		// The existing revoke path's own record.
		if err := auditAs(ctx, tx, evActor, "connection.sealed_revoked", "connection", r.Connection.String(),
			map[string]string{"version": strconv.Itoa(int(r.Version))}); err != nil {
			return reflexdomain.ContainResult{}, err
		}
	}
	return reflexdomain.ContainResult{ActionID: a.ID, Status: string(st)}, nil
}

// addPath records one path.
func addPath(ctx context.Context, q *dbq.Queries, org ids.OrgID, action ids.UUID, typ, subjectType, subjectID string, material bool,
	control string, status rdomain.PathStatus, evidence map[string]string,
) error {
	ev, err := json.Marshal(evidence, json.Deterministic(true))
	if err != nil {
		return err
	}
	return q.InsertResponsePath(ctx, dbq.InsertResponsePathParams{
		OrgID: org, ActionID: action, ID: ids.NewV7(), PathType: typ, SubjectType: subjectType, SubjectID: subjectID,
		Material: material, Control: control, Status: string(status), Evidence: ev,
	})
}

func auditAs(ctx context.Context, tx db.TenantTx, actor evdomain.Actor, name, objType, objID string, details map[string]string) error {
	_, err := auditRecord(ctx, tx, actor, name, objType, objID, details)
	return err
}
