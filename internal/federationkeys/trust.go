// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package federationkeys

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Peer message paths on a peer's server (D1021).
const (
	PathPeerConfirmations = "/federation/v1/peer-confirmations"
	PathPeerRevocations   = "/federation/v1/peer-revocations"
)

// Trust states.
const (
	StateProposed       = "PROPOSED"
	StateConfirmedLocal = "CONFIRMED_LOCAL"
	StateActive         = "ACTIVE"
	StateStale          = "STALE"
	StateRevoked        = "REVOKED"
)

// RefreshEvery is how often the daily job refreshes a trust.
const RefreshEvery = 24 * time.Hour

// confirmClaims is a pc-federation-confirm+jws payload.
type confirmClaims struct {
	IssOrg        string `json:"iss_org"`
	AudOrg        string `json:"aud_org"`
	IssKeysDigest string `json:"iss_keys_digest"`
	AudKeysDigest string `json:"aud_keys_digest"`
	SafetyCode    string `json:"safety_code"`
	IAT           int64  `json:"iat"`
	EXP           int64  `json:"exp"`
	JTI           string `json:"jti"`
}

// revokeClaims is a pc-federation-revoke+jws payload.
type revokeClaims struct {
	IssOrg string `json:"iss_org"`
	AudOrg string `json:"aud_org"`
	IAT    int64  `json:"iat"`
	EXP    int64  `json:"exp"`
	JTI    string `json:"jti"`
}

// fetchDocument GETs and verifies a peer document at url: no redirect, at
// most MaxDocumentBytes, signed by its own keys.
func (s *Service) fetchDocument(ctx context.Context, url string) ([]byte, verifiedDocument, error) {
	if !strings.HasPrefix(url, "https://") {
		return nil, verifiedDocument{}, ErrDocument
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, verifiedDocument{}, ErrDocument
	}
	req.Header.Set("Accept", "application/json")
	c := *s.client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := c.Do(req)
	if err != nil {
		return nil, verifiedDocument{}, fmt.Errorf("%w: %w", ErrDocument, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, verifiedDocument{}, ErrDocument
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxDocumentBytes+1))
	if err != nil || len(raw) > MaxDocumentBytes {
		return nil, verifiedDocument{}, ErrDocument
	}
	vd, err := verifyDocument(raw, s.now())
	if err != nil {
		return nil, verifiedDocument{}, err
	}
	if url != DocumentURL(vd.Doc.ServerURL, mustOrg(vd.Doc.OrgID)) || !time.Unix(vd.Doc.ExpiresAt, 0).After(s.now()) {
		return nil, verifiedDocument{}, ErrDocument
	}
	return raw, vd, nil
}

func mustOrg(s string) ids.OrgID {
	o, _ := ids.Parse[ids.Org](s)
	return o
}

// ourDigest is the keys digest of org's live federation keys.
func (s *Service) ourDigest(ctx context.Context, org ids.OrgID) ([sha256.Size]byte, error) {
	if _, err := s.keys.FederationSigners(ctx, org); err != nil {
		return [sha256.Size]byte{}, err
	}
	live, err := s.keys.ListFederationKeys(ctx, org)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	m := map[string]ed25519.PublicKey{}
	for _, k := range live {
		m[k.KID] = k.Public
	}
	return KeysDigest(m), nil
}

// Propose fetches a peer org's document, verifies it, pins its keys and
// computes the safety code both sides' people compare (federation.manage).
func (s *Service) Propose(ctx context.Context, docURL string) (dbq.PcFederationTrust, error) {
	c, err := s.person(ctx, td.PermFederationManage)
	if err != nil {
		return dbq.PcFederationTrust{}, err
	}
	raw, vd, err := s.fetchDocument(ctx, docURL)
	if err != nil {
		return dbq.PcFederationTrust{}, err
	}
	peer, _ := ids.ParseUUID(vd.Doc.OrgID)
	if peer == c.Org.UUID() {
		return dbq.PcFederationTrust{}, ErrDocument
	}
	ours, err := s.ourDigest(ctx, c.Org)
	if err != nil {
		return dbq.PcFederationTrust{}, err
	}
	theirs := KeysDigest(vd.Keys)
	var out dbq.PcFederationTrust
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		var fu *string
		if vd.Doc.FederationURL != "" {
			fu = &vd.Doc.FederationURL
		}
		t, err := dbq.New(tx).InsertFederationTrust(ctx, dbq.InsertFederationTrustParams{
			OrgID: c.Org, ID: ids.NewV7(), PeerOrgID: peer, PeerName: clip(vd.Doc.OrgName, 200), PeerDocUrl: docURL,
			PeerServerUrl: vd.Doc.ServerURL, PeerFederationUrl: fu, PinnedJwks: vd.KeysRaw, PinnedKeysDigest: theirs[:],
			PeerDocument: raw, PeerDocExpiresAt: time.Unix(vd.Doc.ExpiresAt, 0), SafetyCode: SafetyCode(c.Org.UUID(), ours, peer, theirs),
			CreatedBy: actorString(c.Actor()),
		})
		if db.IsUniqueViolation(err) {
			return ErrTrustExists
		} else if err != nil {
			return err
		}
		out = t
		return record(ctx, tx, auditkind.FederationTrustProposed, c.Actor(), "federation_trust", t.ID.String(),
			map[string]string{"peer_org_id": peer.String(), "keys_digest": hex.EncodeToString(theirs[:])})
	})
	return out, err
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	if s == "" {
		return "unnamed organization"
	}
	return s
}

// Confirm is a person's confirmation that the safety code matched, with a
// fresh step-up (federation.manage). The trust is CONFIRMED_LOCAL, or
// ACTIVE when the peer confirmed already; the confirmation is then sent to
// the peer (and again on every refresh until ACTIVE).
func (s *Service) Confirm(ctx context.Context, id ids.UUID) (dbq.PcFederationTrust, error) {
	c, err := s.person(ctx, td.PermFederationManage)
	if err != nil {
		return dbq.PcFederationTrust{}, err
	}
	ours, err := s.ourDigest(ctx, c.Org)
	if err != nil {
		return dbq.PcFederationTrust{}, err
	}
	var out dbq.PcFederationTrust
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		t, err := q.LockFederationTrust(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrTrustNotFound
		} else if err != nil {
			return err
		}
		if t.State != StateProposed {
			return ErrTrustState
		}
		var theirs [sha256.Size]byte
		copy(theirs[:], t.PinnedKeysDigest)
		if SafetyCode(c.Org.UUID(), ours, t.PeerOrgID, theirs) != t.SafetyCode {
			return ErrSafetyCode
		}
		key, err := stepUp(ctx, tx, c)
		if err != nil {
			return err
		}
		state := StateConfirmedLocal
		if t.PeerConfirmedAt != nil {
			state = StateActive
		}
		user := c.Principal.ID
		if err := q.ConfirmFederationTrustLocal(ctx, dbq.ConfirmFederationTrustLocalParams{
			State: state, ConfirmedBy: &user, ConfirmedCredential: &key, OrgID: c.Org, ID: id,
		}); err != nil {
			return err
		}
		if err := record(ctx, tx, auditkind.FederationTrustConfirmed, c.Actor(), "federation_trust", id.String(),
			map[string]string{"security_key": key.String(), "safety_code": t.SafetyCode}); err != nil {
			return err
		}
		if state == StateActive {
			if err := record(ctx, tx, auditkind.FederationTrustActive, c.Actor(), "federation_trust", id.String(), nil); err != nil {
				return err
			}
		}
		out, err = q.GetFederationTrust(ctx, c.Org, id)
		return err
	})
	if err != nil {
		return out, err
	}
	s.sendConfirm(ctx, c.Org, out, ours)
	return out, nil
}

// sendConfirm posts our signed confirmation to the peer, best effort: a
// failure is logged and retried by the refresh.
func (s *Service) sendConfirm(ctx context.Context, org ids.OrgID, t dbq.PcFederationTrust, ours [sha256.Size]byte) {
	now := s.now().Unix()
	claims := confirmClaims{
		IssOrg: org.String(), AudOrg: t.PeerOrgID.String(), IssKeysDigest: hex.EncodeToString(ours[:]),
		AudKeysDigest: hex.EncodeToString(t.PinnedKeysDigest), SafetyCode: t.SafetyCode,
		IAT: now, EXP: now + int64(ConfirmTTL/time.Second), JTI: ids.NewV7().String(),
	}
	if err := s.post(ctx, org, t.PeerServerUrl+PathPeerConfirmations, TypeConfirm, claims); err != nil {
		s.log.WarnContext(ctx, "federation.confirm_not_delivered", slog.String("trust_id", t.ID.String()), slog.String("error", err.Error()))
	}
}

// post signs claims with org's ACTIVE key and POSTs the compact JWS.
func (s *Service) post(ctx context.Context, org ids.OrgID, url, typ string, claims any) error {
	if !strings.HasPrefix(url, "https://") {
		return ErrDocument
	}
	signers, err := s.keys.FederationSigners(ctx, org)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(claims, json.Deterministic(true))
	if err != nil {
		return err
	}
	compact, err := signers[0].Sign(typ, payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(compact))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/jose")
	c := *s.client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("federation: peer answered %d", resp.StatusCode)
	}
	return nil
}

// ReceiveConfirm handles a peer's confirmation (public endpoint, D1021):
// it must verify with the keys pinned for the issuing peer, name this
// org's current keys, the pinned peer keys and the stored safety code, be
// fresh and unused.
func (s *Service) ReceiveConfirm(ctx context.Context, compact string) error {
	var routing confirmClaims
	if err := unverifiedPayload(compact, &routing); err != nil {
		return err
	}
	us, ok1 := ids.ParseUUID(routing.AudOrg)
	peer, ok2 := ids.ParseUUID(routing.IssOrg)
	if ok1 != nil || ok2 != nil {
		return ErrTokenInvalid
	}
	org, _ := ids.FromUUID[ids.Org](us)
	if err := s.enterprise(ctx, org); err != nil {
		return err
	}
	ours, err := s.ourDigest(ctx, org)
	if err != nil {
		return err
	}
	return s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		t, err := q.LockLiveFederationTrustByPeer(ctx, org, peer)
		if db.IsNoRows(err) {
			return ErrNotTrusted
		} else if err != nil {
			return err
		}
		var cl confirmClaims
		if err := verifyPinned(compact, TypeConfirm, t.PinnedJwks, &cl); err != nil {
			return err
		}
		if err := fresh(cl.IAT, cl.EXP, ConfirmTTL, s.now()); err != nil {
			return err
		}
		if cl.IssOrg != peer.String() || cl.AudOrg != org.String() || cl.SafetyCode != t.SafetyCode ||
			cl.IssKeysDigest != hex.EncodeToString(t.PinnedKeysDigest) || cl.AudKeysDigest != hex.EncodeToString(ours[:]) {
			return ErrSafetyCode
		}
		if err := replay(ctx, q, org, peer, "confirm", cl.JTI, cl.EXP); err != nil {
			return err
		}
		switch t.State {
		case StateProposed, StateConfirmedLocal:
		case StateActive:
			return nil // a resent confirmation
		default:
			return ErrTrustState
		}
		state := t.State
		if state == StateConfirmedLocal {
			state = StateActive
		}
		if err := q.SetFederationTrustPeerConfirmed(ctx, state, org, t.ID); err != nil {
			return err
		}
		if err := record(ctx, tx, auditkind.FederationTrustPeerConfirmed, systemActor, "federation_trust", t.ID.String(),
			map[string]string{"peer_org_id": peer.String()}); err != nil {
			return err
		}
		if state == StateActive && t.State != StateActive {
			return record(ctx, tx, auditkind.FederationTrustActive, systemActor, "federation_trust", t.ID.String(), nil)
		}
		return nil
	})
}

// ReceiveRevoke handles a peer's revocation (public endpoint): the trust
// is revoked at once and its federated agents suspended.
func (s *Service) ReceiveRevoke(ctx context.Context, compact string) error {
	var routing revokeClaims
	if err := unverifiedPayload(compact, &routing); err != nil {
		return err
	}
	us, ok1 := ids.ParseUUID(routing.AudOrg)
	peer, ok2 := ids.ParseUUID(routing.IssOrg)
	if ok1 != nil || ok2 != nil {
		return ErrTokenInvalid
	}
	org, _ := ids.FromUUID[ids.Org](us)
	return s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		t, err := q.LockLiveFederationTrustByPeer(ctx, org, peer)
		if db.IsNoRows(err) {
			return ErrNotTrusted
		} else if err != nil {
			return err
		}
		var cl revokeClaims
		if err := verifyPinned(compact, TypeRevoke, t.PinnedJwks, &cl); err != nil {
			return err
		}
		if err := fresh(cl.IAT, cl.EXP, ConfirmTTL, s.now()); err != nil {
			return err
		}
		if cl.IssOrg != peer.String() || cl.AudOrg != org.String() {
			return ErrTokenInvalid
		}
		if err := replay(ctx, q, org, peer, "revoke", cl.JTI, cl.EXP); err != nil {
			return err
		}
		return revokeInTx(ctx, tx, q, org, t, "peer:"+peer.String(), systemActor)
	})
}

// fresh checks a short-lived message's times.
func fresh(iat, exp int64, ttl time.Duration, now time.Time) error {
	i, e := time.Unix(iat, 0), time.Unix(exp, 0)
	if !e.After(i) || e.Sub(i) > ttl || i.After(now.Add(clockSkew)) || !e.After(now.Add(-clockSkew)) {
		return ErrTokenInvalid
	}
	return nil
}

// replay records a peer message id once (FEDERATION_REPLAY).
func replay(ctx context.Context, q *dbq.Queries, org ids.OrgID, peer ids.UUID, kind, jti string, exp int64) error {
	if jti == "" || len(jti) > 128 {
		return ErrTokenInvalid
	}
	n, err := q.InsertFederationReplay(ctx, dbq.InsertFederationReplayParams{
		OrgID: org, PeerOrgID: peer, Kind: kind, Jti: jti, ExpiresAt: time.Unix(exp, 0).Add(clockSkew),
	})
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrReplay
	}
	return nil
}

// revokeInTx revokes t, suspends its federated agents and audits it.
func revokeInTx(ctx context.Context, tx db.TenantTx, q *dbq.Queries, org ids.OrgID, t dbq.PcFederationTrust, by string, actor evdomain.Actor) error {
	if err := q.RevokeFederationTrust(ctx, &by, org, t.ID); err != nil {
		return err
	}
	n, err := q.SuspendFederationAgentsOfTrust(ctx, org, t.ID)
	if err != nil {
		return err
	}
	return record(ctx, tx, auditkind.FederationTrustRevoked, actor, "federation_trust", t.ID.String(),
		map[string]string{"peer_org_id": t.PeerOrgID.String(), "revoked_by": by, "agents_suspended": fmt.Sprint(n)})
}

// Revoke ends a trust at once (federation.manage): its federated agents
// are suspended, and the peer is told, best effort.
func (s *Service) Revoke(ctx context.Context, id ids.UUID) (dbq.PcFederationTrust, error) {
	c, err := s.caller(ctx, td.PermFederationManage)
	if errors.Is(err, ErrEdition) {
		err = nil // revoking only narrows: a lapsed org can still revoke
	}
	if err != nil {
		return dbq.PcFederationTrust{}, err
	}
	if !c.Human() {
		return dbq.PcFederationTrust{}, ErrPersonOnly
	}
	var out dbq.PcFederationTrust
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		t, err := q.LockFederationTrust(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrTrustNotFound
		} else if err != nil {
			return err
		}
		if t.State == StateRevoked {
			return ErrTrustState
		}
		if err := revokeInTx(ctx, tx, q, c.Org, t, actorString(c.Actor()), c.Actor()); err != nil {
			return err
		}
		out, err = q.GetFederationTrust(ctx, c.Org, id)
		return err
	})
	if err != nil {
		return out, err
	}
	now := s.now().Unix()
	if err := s.post(ctx, c.Org, out.PeerServerUrl+PathPeerRevocations, TypeRevoke, revokeClaims{
		IssOrg: c.Org.String(), AudOrg: out.PeerOrgID.String(), IAT: now, EXP: now + int64(ConfirmTTL/time.Second), JTI: ids.NewV7().String(),
	}); err != nil {
		s.log.WarnContext(ctx, "federation.revoke_not_delivered", slog.String("trust_id", id.String()), slog.String("error", err.Error()))
	}
	return out, nil
}

// Refresh refreshes one trust now (federation.manage).
func (s *Service) Refresh(ctx context.Context, id ids.UUID) (dbq.PcFederationTrust, error) {
	c, err := s.person(ctx, td.PermFederationManage)
	if err != nil {
		return dbq.PcFederationTrust{}, err
	}
	return s.refresh(ctx, c.Org, id, c.Actor())
}

// RefreshOrg refreshes the org's trusts not refreshed for RefreshEvery
// (the daily job); it returns how many it refreshed.
func (s *Service) RefreshOrg(ctx context.Context, org ids.OrgID) (int, error) {
	var due []ids.UUID
	cutoff := s.now().Add(-RefreshEvery)
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		due, err = dbq.New(tx).ListFederationTrustsToRefresh(ctx, org, &cutoff, 100)
		return err
	}, db.ReadOnly())
	if err != nil {
		return 0, err
	}
	n := 0
	for _, id := range due {
		if _, err := s.refresh(ctx, org, id, systemActor); err != nil {
			s.log.WarnContext(ctx, "federation.refresh_failed", slog.String("trust_id", id.String()), slog.String("error", err.Error()))
			continue
		}
		n++
	}
	return n, nil
}

// refresh re-reads the peer's document. New keys are pinned only when the
// document is also signed by a currently pinned key; otherwise the old
// pins stay and peer_rotation_unverified is audited. A trust whose
// document expired and could not be refreshed is STALE until a refresh
// succeeds. A CONFIRMED_LOCAL trust resends its confirmation.
func (s *Service) refresh(ctx context.Context, org ids.OrgID, id ids.UUID, actor evdomain.Actor) (dbq.PcFederationTrust, error) {
	var t dbq.PcFederationTrust
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		t, err = dbq.New(tx).GetFederationTrust(ctx, org, id)
		if db.IsNoRows(err) {
			return ErrTrustNotFound
		}
		return err
	}, db.ReadOnly())
	if err != nil {
		return t, err
	}
	if t.State == StateRevoked {
		return t, ErrTrustState
	}
	raw, vd, ferr := s.fetchDocument(ctx, t.PeerDocUrl)
	ours, err := s.ourDigest(ctx, org)
	if err != nil {
		return t, err
	}
	var out dbq.PcFederationTrust
	err = s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		cur, err := q.LockFederationTrust(ctx, org, id)
		if err != nil {
			return err
		}
		if cur.State == StateRevoked {
			return ErrTrustState
		}
		if ferr != nil || vd.Doc.OrgID != cur.PeerOrgID.String() {
			if s.now().After(cur.PeerDocExpiresAt) && cur.State == StateActive {
				if err := q.SetFederationTrustState(ctx, StateStale, org, id); err != nil {
					return err
				}
				if err := record(ctx, tx, auditkind.FederationTrustStale, actor, "federation_trust", id.String(), nil); err != nil {
					return err
				}
			}
			out, err = q.GetFederationTrust(ctx, org, id)
			if err != nil {
				return err
			}
			return nil
		}
		theirs := KeysDigest(vd.Keys)
		pinsRaw, digest := vd.KeysRaw, theirs[:]
		if !bytes.Equal(theirs[:], cur.PinnedKeysDigest) && !signedByPinned(vd, cur.PinnedJwks) {
			// Keep the old pins: the new keys are not vouched for by a pinned one.
			pinsRaw, digest = cur.PinnedJwks, cur.PinnedKeysDigest
			if err := record(ctx, tx, auditkind.FederationPeerRotationUnverified, actor, "federation_trust", id.String(),
				map[string]string{"keys_digest": hex.EncodeToString(theirs[:])}); err != nil {
				return err
			}
		}
		var pinnedDigest [sha256.Size]byte
		copy(pinnedDigest[:], digest)
		var fu *string
		if vd.Doc.FederationURL != "" {
			fu = &vd.Doc.FederationURL
		}
		if err := q.UpdateFederationTrustPeer(ctx, dbq.UpdateFederationTrustPeerParams{
			PeerName: clip(vd.Doc.OrgName, 200), PeerServerUrl: vd.Doc.ServerURL, PeerFederationUrl: fu, PinnedJwks: pinsRaw,
			PinnedKeysDigest: digest, PeerDocument: raw, PeerDocExpiresAt: time.Unix(vd.Doc.ExpiresAt, 0),
			SafetyCode: SafetyCode(org.UUID(), ours, cur.PeerOrgID, pinnedDigest), OrgID: org, ID: id,
		}); err != nil {
			return err
		}
		if cur.State == StateStale {
			if err := q.SetFederationTrustState(ctx, StateActive, org, id); err != nil {
				return err
			}
		}
		if err := record(ctx, tx, auditkind.FederationTrustRefreshed, actor, "federation_trust", id.String(), nil); err != nil {
			return err
		}
		out, err = q.GetFederationTrust(ctx, org, id)
		return err
	})
	if err != nil {
		return out, err
	}
	if out.State == StateConfirmedLocal {
		s.sendConfirm(ctx, org, out, ours)
	}
	return out, ferr
}

// signedByPinned reports a document signed by a currently pinned key.
func signedByPinned(vd verifiedDocument, pinned []byte) bool {
	var set JWKS
	if json.Unmarshal(pinned, &set) != nil {
		return false
	}
	keys, err := keySet(set)
	if err != nil {
		return false
	}
	for _, kid := range vd.SignedBy {
		if k, ok := keys[kid]; ok && k.Equal(vd.Keys[kid]) {
			return true
		}
	}
	return false
}

// Trusts lists the org's trusts (federation.read).
func (s *Service) Trusts(ctx context.Context, includeRevoked bool) ([]dbq.PcFederationTrust, error) {
	c, err := s.caller(ctx, td.PermFederationRead)
	if err != nil {
		return nil, err
	}
	var out []dbq.PcFederationTrust
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		out, err = dbq.New(tx).ListFederationTrusts(ctx, c.Org, includeRevoked)
		return err
	}, db.ReadOnly())
	return out, err
}

// Trust returns one trust (federation.read).
func (s *Service) Trust(ctx context.Context, id ids.UUID) (dbq.PcFederationTrust, error) {
	c, err := s.caller(ctx, td.PermFederationRead)
	if err != nil {
		return dbq.PcFederationTrust{}, err
	}
	var out dbq.PcFederationTrust
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		out, err = dbq.New(tx).GetFederationTrust(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrTrustNotFound
		}
		return err
	}, db.ReadOnly())
	return out, err
}

// SweepOrg deletes expired replay ids and old call records.
func (s *Service) SweepOrg(ctx context.Context, org ids.OrgID) error {
	return s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if _, err := q.DeleteExpiredFederationReplay(ctx, org); err != nil {
			return err
		}
		_, err := q.DeleteExpiredFederationCalls(ctx, org)
		return err
	})
}
