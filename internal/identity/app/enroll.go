// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"fmt"
	"time"

	agents "github.com/katocxl/pantherclaw/internal/agents/app"
	adomain "github.com/katocxl/pantherclaw/internal/agents/domain"
	"github.com/katocxl/pantherclaw/internal/authn/credential"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// MaxEnrollmentTTL bounds an enrollment token's validity (PAP-1 §3.2).
const MaxEnrollmentTTL = 15 * time.Minute

func agentUsable(a dbq.PcAgent) bool { return adomain.State(a.State).Usable() }

// isOwner reports whether the caller is the agent's owner or backup owner.
// Owners are users, so this is false for every service account and API key.
func isOwner(c tenancy.Caller, a dbq.PcAgent) bool {
	if c.Principal.Kind != td.KindUser {
		return false
	}
	id := c.Principal.ID
	return (a.OwnerUserID != nil && *a.OwnerUserID == id) || (a.BackupOwnerUserID != nil && *a.BackupOwnerUserID == id)
}

// EnrollmentToken is a minted token; Secret is shown once.
type EnrollmentToken struct {
	ID        ids.UUID
	Secret    credential.Token
	ExpiresAt time.Time
}

// CreateEnrollmentToken mints a single-use pce_ token for an agent (PAP-1
// §3.2, PN-002.1). Only the agent's owner or backup owner, holding
// agent.enroll where the agent lives, may mint one; the agent must be
// claimed and usable. The token is stored only as SHA-256.
func (s *Service) CreateEnrollmentToken(ctx context.Context, agentID ids.UUID, ttl time.Duration) (EnrollmentToken, error) {
	if ttl <= 0 || ttl > MaxEnrollmentTTL {
		ttl = MaxEnrollmentTTL
	}
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return EnrollmentToken{}, err
	}
	var out EnrollmentToken
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		a, err := usableOrMissing(ctx, c, q, agentID, td.PermAgentEnroll)
		if err != nil {
			return err
		}
		if !isOwner(c, a) {
			return ErrNotOwner
		}
		tok, err := credential.New(credential.EnrollmentToken, "", c.Org)
		if err != nil {
			return err
		}
		r, err := q.InsertEnrollmentToken(ctx, dbq.InsertEnrollmentTokenParams{
			OrgID: c.Org, ID: ids.NewV7(), AgentID: a.ID, EnvironmentID: *a.EnvironmentID, TokenHash: tok.Hash(),
			CreatedBy: c.Principal.String(), TtlMinutes: int32(ttl / time.Minute), //nolint:gosec // G115: at most 15
		})
		if err != nil {
			return err
		}
		out = EnrollmentToken{ID: r.ID, Secret: tok, ExpiresAt: r.ExpiresAt}
		return callerRecord(ctx, tx, c, "identity.enrollment_token_created", a.ID, map[string]string{"enrollment_id": r.ID.String()})
	})
	return out, err
}

// usableOrMissing loads an agent the caller may act on with p; another
// org's or an unreadable agent is NotFound.
func usableOrMissing(ctx context.Context, c tenancy.Caller, q *dbq.Queries, id ids.UUID, p td.Permission) (dbq.PcAgent, error) {
	a, err := q.LockAgent(ctx, c.Org, id)
	if db.IsNoRows(err) {
		return a, ErrAgentNotFound
	} else if err != nil {
		return a, err
	}
	path, err := agents.PathOf(ctx, q, a)
	if err != nil {
		return a, err
	}
	if err := c.Require(p, path); err != nil {
		return a, err
	}
	if !agentUsable(a) {
		return a, ErrAgentUnusable
	}
	return a, nil
}

// EnrollInput is a workload's enrollment request (PAP-1 §3.2).
type EnrollInput struct {
	// Proof is the verified key-only proof of the request.
	Proof           pap.Checked
	EnrollmentToken string
	// Attestation is optional L2 evidence; without an enrollment token it
	// must match an auto-admitting issuer entry.
	Attestation *Attestation
	PublicJWK   []byte
	// DeclaredRelease is what the workload reports about itself: always
	// "declared" (PAP-1 §3.3).
	DeclaredRelease string
	ClientAddress   string
}

// Enrolled describes a new instance.
type Enrolled struct {
	Instance    pap.Instance
	State       string
	Fingerprint string
	// Level is the attestation level the instance's tokens carry once it
	// is admitted.
	Level int
}

var errReused = errors.New("identity: enrollment token reused")

// Enroll registers the proof's key as an instance of an agent (PAP-1
// §3.2). An enrollment token, when sent, names the agent; it is consumed
// exactly once and reusing it is refused and audited (PN-002.1, T-004). An
// attestation, when sent, must match an active entry of that agent and
// makes the instance L2. The instance waits in PENDING_ADMISSION, with an
// ADMISSION entry showing the fingerprint to the owner, unless the matching
// entry auto-admits and the agent can be L2: that entry is an activated,
// human-approved policy for exactly these claims (HR-094, HR-141), so the
// instance is admitted at once whether or not an enrollment token came
// with it. Without an enrollment token, the attestation's audience names
// the org, the entry names the agent, and only an auto-admitting entry
// enrolls. The attestation is consumed in the same transaction.
func (s *Service) Enroll(ctx context.Context, in EnrollInput) (Enrolled, error) {
	if _, ok := in.Proof.Token(); ok {
		return Enrolled{}, pap.Err(pap.CodeInvalidProof) // enrollment uses a key-only proof
	}
	var jwk jws.JWK
	if err := json.Unmarshal(in.PublicJWK, &jwk); err != nil {
		return Enrolled{}, pap.Err(pap.CodeKeyMismatch)
	}
	pub, err := jwk.Key()
	if err != nil || jws.Thumbprint(pub) != in.Proof.JKT() || !pub.Equal(in.Proof.Key()) {
		return Enrolled{}, pap.Err(pap.CodeKeyMismatch)
	}
	var tok credential.Token
	var org ids.OrgID
	switch {
	case in.EnrollmentToken != "":
		if tok, err = credential.Parse(credential.EnrollmentToken, in.EnrollmentToken); err != nil {
			return Enrolled{}, pap.Err(pap.CodeInvalidToken)
		}
		org = tok.Org()
	case in.Attestation != nil:
		if org = s.AttestationOrg(*in.Attestation); org.IsZero() {
			return Enrolled{}, attErr(errors.New("the audience names no org"))
		}
	default:
		return Enrolled{}, pap.Err(pap.CodeInvalidToken)
	}
	if err := s.Consume(ctx, org, in.Proof); err != nil {
		return Enrolled{}, err
	}
	var cands []attested
	if in.Attestation != nil {
		if cands, err = s.attest(ctx, org, *in.Attestation); err != nil {
			return Enrolled{}, err
		}
	}
	var out Enrolled
	err = s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		var a dbq.PcAgent
		var enrollment *ids.UUID
		if in.EnrollmentToken != "" {
			et, err := q.ConsumeEnrollmentToken(ctx, org, tok.Hash())
			if db.IsNoRows(err) {
				if prev, err := q.GetEnrollmentTokenByHash(ctx, org, tok.Hash()); err == nil && prev.State == "USED" {
					return errReused
				}
				return pap.Err(pap.CodeInvalidToken)
			} else if err != nil {
				return err
			}
			if a, err = usableAgent(ctx, q, org, et.AgentID); err != nil {
				return pap.Err(pap.CodeInstanceNotAdmitted)
			}
			enrollment = &et.ID
		}
		var pick *attested
		if in.Attestation != nil {
			var agent *ids.UUID
			if enrollment != nil {
				agent = &a.ID
			}
			p, err := choose(cands, agent)
			if err != nil {
				return err
			}
			if enrollment == nil {
				if a, err = usableAgent(ctx, q, org, p.rev.AgentID); err != nil {
					return attErr(err)
				}
			}
			pick = &p
		}
		out, err = s.insertInstance(ctx, q, tx, org, a, in, enrollment, pick, pub)
		return err
	})
	if errors.Is(err, errReused) {
		s.auditReuse(ctx, org, tok.Hash())
		return Enrolled{}, pap.Err(pap.CodeInvalidToken)
	}
	return out, err
}

// auditReuse records a reused enrollment token in its own transaction, so
// the refusal leaves evidence.
func (s *Service) auditReuse(ctx context.Context, org ids.OrgID, hash []byte) {
	_ = s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		et, err := dbq.New(tx).GetEnrollmentTokenByHash(ctx, org, hash)
		if err != nil {
			return err
		}
		return recordAs(ctx, tx, evdomainSystem(), "security.enrollment_token_reused", "agent", et.AgentID,
			map[string]string{"enrollment_id": et.ID.String()})
	})
}

// maxLevel is the highest level an agent's instances reach (HR-092: a
// desktop agent stays L1).
func maxLevel(a dbq.PcAgent) int {
	if a.ExecutionContext == nil {
		return 1
	}
	return adomain.ExecutionContext(*a.ExecutionContext).MaxAttestationLevel()
}

// insertInstance stores the instance; a pending one gets an ADMISSION entry
// and an auto-admitted one marks the agent verified.
func (s *Service) insertInstance(ctx context.Context, q *dbq.Queries, tx db.TenantTx, org ids.OrgID, a dbq.PcAgent,
	in EnrollInput, enrollment *ids.UUID, pick *attested, pub ed25519.PublicKey,
) (Enrolled, error) {
	level := 1
	if pick != nil && maxLevel(a) >= 2 {
		level = 2
	}
	auto := pick != nil && pick.rev.AutoAdmit && level == 2
	if enrollment == nil && !auto {
		return Enrolled{}, attErr(errors.New("without an enrollment token, only an auto-admitting entry enrolls an L2 agent"))
	}
	jkt := jws.Thumbprint(pub)
	if exists, err := q.InstanceExistsForKey(ctx, org, jkt); err != nil {
		return Enrolled{}, err
	} else if exists {
		return Enrolled{}, ErrKeyEnrolled
	}
	canonical, err := json.Marshal(jws.JWK{Kty: "OKP", Crv: "Ed25519", X: b64(pub)})
	if err != nil {
		return Enrolled{}, err
	}
	var relState, relDigest *string
	switch {
	case pick != nil && pick.match.ReleaseDigest != "":
		relState, relDigest = ptr(pap.ReleaseAttested), ptr(pick.match.ReleaseDigest)
	case in.DeclaredRelease != "":
		relState, relDigest = ptr(pap.ReleaseDeclared), &in.DeclaredRelease
	}
	id, via := ids.NewV7(), "enrollment_token"
	if enrollment == nil {
		via = "attestation"
	}
	var r dbq.PcAgentInstance
	if pick == nil {
		r, err = q.InsertInstance(ctx, dbq.InsertInstanceParams{
			OrgID: org, ID: id, AgentID: a.ID, Jkt: jkt, PublicJwk: canonical, EnrolledVia: via,
			EnrollmentTokenID: enrollment, ReleaseState: relState, ReleaseDigest: relDigest, LastNetwork: optString(network(in.ClientAddress)),
		})
	} else {
		state, decidedBy := "PENDING_ADMISSION", (*string)(nil)
		if auto {
			state, decidedBy = "ADMITTED", ptr("trusted_issuer:"+pick.rev.EntryID.String())
		}
		var binding []byte
		if binding, err = json.Marshal(pick.match.Binding); err != nil {
			return Enrolled{}, err
		}
		r, err = q.InsertAttestedInstance(ctx, dbq.InsertAttestedInstanceParams{
			OrgID: org, ID: id, AgentID: a.ID, Jkt: jkt, PublicJwk: canonical, State: state, EnrolledVia: via,
			EnrollmentTokenID: enrollment, IssuerRevisionID: &pick.rev.ID, Binding: binding, AttestedUntil: &pick.window.ExpiresAt,
			ReleaseState: relState, ReleaseDigest: relDigest, LastNetwork: optString(network(in.ClientAddress)), DecidedBy: decidedBy,
		})
	}
	if db.IsUniqueViolation(err) {
		return Enrolled{}, ErrKeyEnrolled
	} else if err != nil {
		return Enrolled{}, err
	}
	if pick != nil {
		if err := pick.record(ctx, q, org, id); err != nil {
			return Enrolled{}, err
		}
	}
	if !auto {
		if err := pendingEntry(ctx, q, org, a, r, in, enrollment, pick); err != nil {
			return Enrolled{}, err
		}
	}
	if err := agents.RecordChange(ctx, q, org, a.ID, adomain.Change{
		Kind: adomain.ChangeInstanceEnrolled, Actor: adomain.InstanceActor(id),
		Details: map[string]string{"instance_id": id.String(), "fingerprint": jkt, "enrolled_via": via},
	}); err != nil {
		return Enrolled{}, err
	}
	if err := recordAs(ctx, tx, instanceActor(id), "identity.instance_enrolled", "instance", id,
		map[string]string{"agent_id": a.ID.String(), "fingerprint": jkt, "enrolled_via": via}); err != nil {
		return Enrolled{}, err
	}
	if auto {
		if err := autoAdmitted(ctx, q, tx, org, a, id, pick.rev); err != nil {
			return Enrolled{}, err
		}
	}
	return Enrolled{
		Instance: pap.Instance{Org: org, Agent: a.ID, Instance: r.ID}, State: r.State, Fingerprint: jkt, Level: level,
	}, nil
}

// pendingEntry opens the ADMISSION entry the owner decides on. Attested
// claims are trusted evidence; what the workload reports is not.
func pendingEntry(ctx context.Context, q *dbq.Queries, org ids.OrgID, a dbq.PcAgent, r dbq.PcAgentInstance,
	in EnrollInput, enrollment *ids.UUID, pick *attested,
) error {
	trusted := map[string]string{"fingerprint": r.Jkt, "enrolled_via": r.EnrolledVia}
	if enrollment != nil {
		trusted["enrollment_id"] = enrollment.String()
	}
	if pick != nil {
		trusted = withClaims(pick.match.Binding, trusted)
		trusted["issuer"], trusted["issuer_entry_id"] = pick.issuer, pick.rev.EntryID.String()
		if pick.match.ReleaseDigest != "" {
			trusted["attested_release_digest"] = pick.match.ReleaseDigest
		}
	}
	ev, err := json.Marshal(map[string]map[string]string{
		"trusted":   trusted,
		"untrusted": {"declared_release_digest": in.DeclaredRelease, "client_network": network(in.ClientAddress)},
	})
	if err != nil {
		return err
	}
	_, err = q.InsertWaitlistEntry(ctx, dbq.InsertWaitlistEntryParams{
		OrgID: org, ID: ids.NewV7(), SubjectType: "instance", SubjectID: r.ID, AgentID: a.ID, Evidence: ev,
	})
	return err
}

// autoAdmitted records an admission made by an issuer entry (HR-094).
func autoAdmitted(ctx context.Context, q *dbq.Queries, tx db.TenantTx, org ids.OrgID, a dbq.PcAgent, id ids.UUID,
	rev dbq.PcTrustedIssuer,
) error {
	if err := agents.MarkVerified(ctx, q, org, a.ID, adomain.System); err != nil {
		return err
	}
	details := map[string]string{
		"instance_id": id.String(), "issuer_entry_id": rev.EntryID.String(), "issuer_revision": fmt.Sprint(rev.Revision),
	}
	if err := agents.RecordChange(ctx, q, org, a.ID, adomain.Change{
		Kind: adomain.ChangeInstanceAutoAdmitted, Actor: adomain.System, Details: details,
	}); err != nil {
		return err
	}
	details["agent_id"] = a.ID.String()
	return recordAs(ctx, tx, evdomainSystem(), "identity.instance_auto_admitted", "instance", id, details)
}
