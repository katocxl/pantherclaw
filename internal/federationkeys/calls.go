// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package federationkeys

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/katocxl/pantherclaw/internal/authority"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/telemetry"
)

// Federation calls (D1024c, D1024d, D1025): the authority.Federation the
// Authority uses.

var _ authority.Federation = (*Calls)(nil)

// Calls admits federation calls and signs and records their receipts.
type Calls struct{ s *Service }

// Calls returns the Authority's federation store and signer.
func (s *Service) Calls() *Calls { return &Calls{s: s} }

// tokenClaims is a pap-fed+jwt payload.
type tokenClaims struct {
	Iss string   `json:"iss"`
	Aud string   `json:"aud"`
	Sub string   `json:"sub"`
	IAT int64    `json:"iat"`
	EXP int64    `json:"exp"`
	JTI string   `json:"jti"`
	Pap tokenPap `json:"pap"`
}

type tokenPap struct {
	V              int    `json:"v"`
	Fed            int    `json:"fed"`
	AttLvl         int    `json:"att_lvl"`
	Action         string `json:"action"`
	Txn            string `json:"txn"`
	Listing        string `json:"listing"`
	Htm            string `json:"htm"`
	Htu            string `json:"htu"`
	Bh             string `json:"bh"`
	DecisionDigest string `json:"decision_digest"`
}

// receiptClaims is a pap-fed-receipt+jwt payload.
type receiptClaims struct {
	Iss string     `json:"iss"`
	Aud string     `json:"aud"`
	IAT int64      `json:"iat"`
	JTI string     `json:"jti"`
	Pap receiptPap `json:"pap"`
}

type receiptPap struct {
	V          int    `json:"v"`
	Kind       string `json:"kind"`
	Decision   string `json:"decision"`
	Action     string `json:"action"`
	PeerAction string `json:"peer_action"`
	Txn        string `json:"txn,omitzero"`
	Listing    string `json:"listing"`
	ReqDigest  string `json:"req_digest"`
}

// Receipt decisions.
const (
	DecisionAllow = "ALLOW"
	DecisionDeny  = "DENY"
	DecisionHeld  = "HELD"
)

var errOutboundUnknown = pcerr.New(pcerr.NotFound, "FEDERATION_ACTION_UNKNOWN",
	"no federation action of this gateway has that id")

func bh(body [sha256.Size]byte) string { return base64.RawURLEncoding.EncodeToString(body[:]) }

// StartCall verifies a peer's pap-fed+jwt once and admits the call
// (authority.Federation): an ACTIVE trust for its issuer, a pinned kid,
// addressed to this org, at most 60 s long, POST to exactly this listing's
// URL on our federation face with this body, a federated agent of the peer
// agent and an active cross-org grant to it. It ensures the agent's day run
// and stores the 60-second call record.
func (c *Calls) StartCall(ctx context.Context, org ids.OrgID, _ string, in authority.FederatedCallInput) (authority.FederatedCall, error) {
	s := c.s
	if err := s.enterprise(ctx, org); err != nil {
		return authority.FederatedCall{}, err
	}
	if kid, typ, err := jws.Unverified(in.Credential); err != nil || typ != TypeToken || kid == "" {
		return authority.FederatedCall{}, ErrTokenInvalid
	}
	var routing tokenClaims
	if err := unverifiedPayload(in.Credential, &routing); err != nil {
		return authority.FederatedCall{}, err
	}
	peer, ok := peerOrgOf(routing.Iss)
	if !ok {
		return authority.FederatedCall{}, ErrTokenInvalid
	}
	var out authority.FederatedCall
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		t, err := q.GetLiveFederationTrustByPeer(ctx, org, peer)
		if db.IsNoRows(err) {
			return ErrNotTrusted
		} else if err != nil {
			return err
		}
		switch t.State {
		case StateActive:
		case StateStale:
			return ErrPeerStale
		default:
			return ErrNotTrusted
		}
		var cl tokenClaims
		if err := verifyPinned(in.Credential, TypeToken, t.PinnedJwks, &cl); err != nil {
			return err
		}
		fu, err := s.federationURL(ctx, q, org)
		if err != nil {
			return err
		}
		if err := checkToken(cl, peer, org, fu, in, s.now()); err != nil {
			return err
		}
		if err := replay(ctx, q, org, peer, "token", cl.JTI, cl.EXP); err != nil {
			return err
		}
		l, err := q.GetActiveFederationListingByName(ctx, org, in.Listing)
		if db.IsNoRows(err) {
			return ErrListingUnknown
		} else if err != nil {
			return err
		}
		fa, err := q.GetFederationAgent(ctx, org, t.ID, cl.Sub)
		if db.IsNoRows(err) && agentPart(cl.Sub) != cl.Sub {
			fa, err = q.GetFederationAgent(ctx, org, t.ID, agentPart(cl.Sub))
		}
		if db.IsNoRows(err) {
			return ErrNotTrusted
		} else if err != nil {
			return err
		}
		if fa.EnvironmentID == nil {
			return ErrNotTrusted
		}
		grant, err := q.FindCrossOrgGrant(ctx, dbq.FindCrossOrgGrantParams{
			OrgID: org, PeerOrgID: &peer, PeerAgents: []string{cl.Sub, agentPart(cl.Sub)}, AgentID: fa.AgentID,
		})
		if db.IsNoRows(err) {
			return ErrNotTrusted
		} else if err != nil {
			return err
		}
		run, err := dayRun(ctx, q, org, t, fa, grant, s.now())
		if err != nil {
			return err
		}
		callID, receiptID := ids.NewV7(), ids.NewV7()
		var body [sha256.Size]byte = in.BodySHA256
		expires, err := q.InsertFederationCall(ctx, dbq.InsertFederationCallParams{
			OrgID: org, ID: callID, TrustID: t.ID, PeerAgent: fa.PeerAgent, RunID: run, AgentID: fa.AgentID,
			InstanceID: fa.InstanceID, Listing: l.Name, Htu: in.HTU, BodySha256: body[:], ReceiptID: receiptID,
			PeerActionID: cl.Pap.Action, PeerToken: in.Credential, PeerAttLvl: int16(cl.Pap.AttLvl), //nolint:gosec // 0..3, checked
		})
		if err != nil {
			return err
		}
		out = authority.FederatedCall{
			ID: callID, Run: run, Agent: fa.AgentID, Instance: fa.InstanceID, Env: *fa.EnvironmentID, Connection: l.ConnectionID,
			TrustID: t.ID, PeerOrg: peer, ReceiptID: receiptID, PeerAgent: fa.PeerAgent, PeerActionID: cl.Pap.Action,
			Listing: l.Name, HTU: in.HTU, BodySHA256: body, Expires: expires, AgentState: fa.AgentState,
			JKT: syntheticJKT(t.ID, fa.PeerAgent), AttLevel: cl.Pap.AttLvl, PeerToken: in.Credential,
		}
		return nil
	})
	return out, err
}

// checkToken checks a verified token's claims against the request.
func checkToken(cl tokenClaims, peer ids.UUID, org ids.OrgID, federationURL string, in authority.FederatedCallInput, now time.Time) error {
	if err := fresh(cl.IAT, cl.EXP, TokenTTL, now); err != nil {
		return err
	}
	switch {
	case cl.Iss != orgSubject(peer), cl.Aud != orgSubject(org.UUID()),
		!strings.HasPrefix(cl.Sub, orgSubject(peer)+"/agent/"),
		cl.Pap.V != 1, cl.Pap.Fed != 1, cl.Pap.Htm != "POST",
		federationURL == "", in.HTU != FaceURL(federationURL, in.Listing), cl.Pap.Htu != in.HTU,
		cl.Pap.Listing != in.Listing,
		subtle.ConstantTimeCompare([]byte(cl.Pap.Bh), []byte(bh(in.BodySHA256))) != 1,
		cl.Pap.Action == "" || len(cl.Pap.Action) > 128, cl.Pap.AttLvl < 0 || cl.Pap.AttLvl > 3:
		return ErrTokenInvalid
	}
	return nil
}

// dayRun returns the federated agent's run for today (UTC), creating it
// with its grant.
func dayRun(ctx context.Context, q *dbq.Queries, org ids.OrgID, t dbq.PcFederationTrust, fa dbq.GetFederationAgentRow,
	grant ids.UUID, now time.Time,
) (ids.UUID, error) {
	day := now.UTC().Truncate(24 * time.Hour)
	d := pgtype.Date{Time: day, Valid: true}
	trust, peer, peerAgent := t.ID, t.PeerOrgID, fa.PeerAgent
	r, err := q.GetActiveFederationRun(ctx, dbq.GetActiveFederationRunParams{
		OrgID: org, FederationTrustID: &trust, PeerAgent: &peerAgent, FederationDay: d,
	})
	if err == nil && r.GrantID != nil && *r.GrantID == grant {
		return r.ID, nil
	} else if err != nil && !db.IsNoRows(err) {
		return ids.UUID{}, err
	}
	if err == nil {
		// The day run is on an older grant; the new grant starts a new run
		// only once that one ends.
		return r.ID, nil
	}
	id, inst, env := ids.NewV7(), fa.InstanceID, *fa.EnvironmentID
	if err := q.InsertFederationRun(ctx, dbq.InsertFederationRunParams{
		OrgID: org, ID: id, AgentID: fa.AgentID, InstanceID: &inst, EnvironmentID: env, GrantID: &grant,
		TaskRef: "federation " + t.PeerName, ExpiresAt: day.Add(24 * time.Hour), FederationTrustID: &trust,
		PeerOrgID: &peer, PeerAgent: &peerAgent, FederationDay: d,
	}); err != nil {
		return ids.UUID{}, err
	}
	return id, nil
}

// UseCall consumes an admitted call for action once (authority.Federation).
func (c *Calls) UseCall(ctx context.Context, org ids.OrgID, call, action ids.UUID) (authority.FederatedCall, error) {
	var out authority.FederatedCall
	err := c.s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		row, err := q.UseFederationCall(ctx, &action, org, call)
		if db.IsNoRows(err) {
			return ErrTokenInvalid
		} else if err != nil {
			return err
		}
		t, err := q.GetFederationTrust(ctx, org, row.TrustID)
		if err != nil {
			return err
		}
		switch t.State {
		case StateActive:
		case StateStale:
			return ErrNotTrusted // a STALE trust refuses every decision (D1024)
		default:
			return ErrNotTrusted
		}
		fa, err := q.GetFederationAgent(ctx, org, row.TrustID, row.PeerAgent)
		if db.IsNoRows(err) || (err == nil && fa.EnvironmentID == nil) {
			return ErrNotTrusted
		} else if err != nil {
			return err
		}
		l, err := q.GetActiveFederationListingByName(ctx, org, row.Listing)
		if db.IsNoRows(err) {
			return ErrListingUnknown
		} else if err != nil {
			return err
		}
		out = authority.FederatedCall{
			ID: row.ID, Run: row.RunID, Agent: row.AgentID, Instance: row.InstanceID, Env: *fa.EnvironmentID,
			Connection: l.ConnectionID, TrustID: t.ID, PeerOrg: t.PeerOrgID, ReceiptID: row.ReceiptID, PeerAgent: row.PeerAgent,
			PeerActionID: row.PeerActionID, Listing: row.Listing, HTU: row.Htu, Expires: row.ExpiresAt, AgentState: fa.AgentState,
			JKT: syntheticJKT(t.ID, row.PeerAgent), AttLevel: int(row.PeerAttLvl), PeerToken: row.PeerToken,
		}
		copy(out.BodySHA256[:], row.BodySha256)
		return nil
	})
	return out, err
}

// SignAnswer signs the minimal pap-fed-receipt+jwt for the decision on a
// call at decision time and stores it as the call's IN receipt
// (authority.Federation, D1024d).
func (c *Calls) SignAnswer(ctx context.Context, org ids.OrgID, call authority.FederatedCall, action ids.UUID, decision string) (string, error) {
	signers, err := c.s.keys.FederationSigners(ctx, org)
	if err != nil {
		return "", err
	}
	cl := receiptClaims{
		Iss: orgSubject(org.UUID()), Aud: orgSubject(call.PeerOrg), IAT: c.s.now().Unix(), JTI: ids.NewV7().String(),
		Pap: receiptPap{
			V: 1, Kind: "federation", Decision: decision, Action: action.String(), PeerAction: call.PeerActionID,
			Listing: call.Listing, ReqDigest: bh(call.BodySHA256),
		},
	}
	payload, err := json.Marshal(cl, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	compact, err := signers[0].Sign(TypeReceipt, payload)
	if err != nil {
		return "", err
	}
	err = c.s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		peerAction, peerToken := call.PeerActionID, call.PeerToken
		return dbq.New(tx).InsertFederationReceipt(ctx, dbq.InsertFederationReceiptParams{
			OrgID: org, ID: call.ReceiptID, Direction: "IN", TrustID: call.TrustID, PeerOrgID: call.PeerOrg,
			ActionID: &action, PeerActionID: &peerAction, Decision: &decision, ReceiptJws: &peerToken, State: "VALID",
		})
	})
	if err != nil {
		return "", err
	}
	return compact, nil
}

// IssueToken signs a pap-fed+jwt for one of our ALLOWED actions on a
// federated peer's listing connection, to exactly that listing's URL on
// the peer's federation face (authority.Federation, D1025).
func (c *Calls) IssueToken(ctx context.Context, org ids.OrgID, gatewayID string, action ids.UUID, body [sha256.Size]byte, htu string) (string, time.Time, error) {
	s := c.s
	if err := s.enterprise(ctx, org); err != nil {
		return "", time.Time{}, err
	}
	var cl tokenClaims
	now := s.now().Truncate(time.Second)
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		a, err := q.FederationOutboundAction(ctx, org, action)
		if db.IsNoRows(err) {
			return errOutboundUnknown
		} else if err != nil {
			return err
		}
		if a.GatewayID != gatewayID || a.FederationTrustID == nil || a.FederationListing == nil || a.InstanceID == nil {
			return errOutboundUnknown
		}
		if a.Decision != "ALLOW" && a.Decision != "ALLOW_WITH_OBLIGATIONS" {
			return pcerr.New(pcerr.FailedPrecondition, "FEDERATION_NOT_ALLOWED", "the action was not allowed")
		}
		t, err := q.GetFederationTrust(ctx, org, *a.FederationTrustID)
		if err != nil {
			return err
		}
		if t.State != StateActive {
			return ErrNotTrusted
		}
		if t.PeerFederationUrl == nil || htu != FaceURL(*t.PeerFederationUrl, *a.FederationListing) {
			return ErrTokenInvalid
		}
		inst, err := q.GetInstance(ctx, org, *a.InstanceID)
		if err != nil {
			return err
		}
		if a.DecisionReceipt == "" {
			return errOutboundUnknown // no signed decision to bind the token to
		}
		digest := sha256.Sum256([]byte(a.DecisionReceipt)) // our decision receipt (D1023)
		cl = tokenClaims{
			Iss: orgSubject(org.UUID()), Aud: orgSubject(t.PeerOrgID),
			Sub: orgSubject(org.UUID()) + "/agent/" + a.AgentID.String() + "/inst/" + a.InstanceID.String(),
			IAT: now.Unix(), EXP: now.Add(TokenTTL).Unix(), JTI: ids.NewV7().String(),
			Pap: tokenPap{
				V: 1, Fed: 1, AttLvl: int(inst.AttLevel), Action: action.String(), Txn: a.TransactionID.String(),
				Listing: *a.FederationListing, Htm: "POST", Htu: htu, Bh: bh(body), DecisionDigest: hex.EncodeToString(digest[:]),
			},
		}
		return nil
	}, db.ReadOnly())
	if err != nil {
		return "", time.Time{}, err
	}
	signers, err := s.keys.FederationSigners(ctx, org)
	if err != nil {
		return "", time.Time{}, err
	}
	payload, err := json.Marshal(cl, json.Deterministic(true))
	if err != nil {
		return "", time.Time{}, err
	}
	tok, err := signers[0].Sign(TypeToken, payload)
	return tok, time.Unix(cl.EXP, 0), err
}

// RecordReceipt verifies the peer's answer receipt with the keys pinned
// for it and stores it as an OUT receipt: VALID, MISSING (none came back)
// or INVALID (authority.Federation, D1025). A VALID DENY or HELD answer is
// PEER_DENIED or PEER_HELD with the agent-safe text.
func (c *Calls) RecordReceipt(ctx context.Context, org ids.OrgID, gatewayID string, action ids.UUID, body [sha256.Size]byte, receipt string,
) (authority.FederationReceiptRecord, error) {
	s := c.s
	var out authority.FederationReceiptRecord
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		a, err := q.FederationOutboundAction(ctx, org, action)
		if db.IsNoRows(err) {
			return errOutboundUnknown
		} else if err != nil {
			return err
		}
		if a.GatewayID != gatewayID || a.FederationTrustID == nil || a.FederationListing == nil {
			return errOutboundUnknown
		}
		t, err := q.GetFederationTrust(ctx, org, *a.FederationTrustID)
		if err != nil {
			return err
		}
		row := dbq.InsertFederationReceiptParams{
			OrgID: org, ID: ids.NewV7(), Direction: "OUT", TrustID: t.ID, PeerOrgID: t.PeerOrgID, ActionID: &action,
		}
		var cl receiptClaims
		switch {
		case receipt == "":
			row.State = "MISSING"
		case verifyPinned(receipt, TypeReceipt, t.PinnedJwks, &cl) != nil || !validReceipt(cl, t.PeerOrgID, org, action, *a.FederationListing, bh(body), s.now()):
			row.State, row.ReceiptJws = "INVALID", &receipt
		default:
			d, peerAction := cl.Pap.Decision, cl.Pap.Action
			row.State, row.ReceiptJws, row.Decision, row.PeerActionID = "VALID", &receipt, &d, &peerAction
		}
		if err := q.InsertFederationReceipt(ctx, row); err != nil {
			return err
		}
		out.State = row.State
		if row.Decision != nil {
			out.Decision = *row.Decision
		}
		return nil
	})
	if err != nil {
		return out, err
	}
	switch out.State {
	case "MISSING", "INVALID":
		telemetry.FederationReceiptProblem(ctx, out.State)
	}
	switch out.Decision {
	case DecisionDeny:
		out.Reason, out.AgentText = "PEER_DENIED", AgentTextRefused
	case DecisionHeld:
		out.Reason, out.AgentText = "PEER_HELD", AgentTextHeld
	}
	return out, nil
}

// validReceipt checks a verified receipt's claims: from the peer, to us,
// about our action on this listing, recent, with a known decision.
func validReceipt(cl receiptClaims, peer ids.UUID, org ids.OrgID, action ids.UUID, listing, reqDigest string, now time.Time) bool {
	iat := time.Unix(cl.IAT, 0)
	return cl.Iss == orgSubject(peer) && cl.Aud == orgSubject(org.UUID()) && cl.Pap.V == 1 && cl.Pap.Kind == "federation" &&
		cl.Pap.PeerAction == action.String() && cl.Pap.Listing == listing && cl.Pap.ReqDigest == reqDigest &&
		(cl.Pap.Decision == DecisionAllow || cl.Pap.Decision == DecisionDeny || cl.Pap.Decision == DecisionHeld) &&
		cl.Pap.Action != "" && len(cl.Pap.Action) <= 128 &&
		!iat.After(now.Add(clockSkew)) && now.Sub(iat) <= ConfirmTTL
}
