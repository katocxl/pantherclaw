// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/approvals/proof"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// permitType is the JWS typ of dispatch permits (authority.TypePermit; the
// gateway cannot import the Authority, which has database access).
const permitType = "pap-permit+jwt"

// jwksRefreshEvery bounds JWKS refetches triggered by unknown kids.
const jwksRefreshEvery = time.Second

// ErrPermitInvalid reports a permit that must not be used for dispatch.
var ErrPermitInvalid = errors.New("gateway: permit invalid")

// permitClaims mirrors the Authority's permit payload.
type permitClaims struct {
	Iss string `json:"iss"`
	Aud string `json:"aud"`
	Jti string `json:"jti"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
	Pap struct {
		V     int    `json:"v"`
		Org   string `json:"org"`
		Txn   string `json:"txn"`
		Act   string `json:"act"`
		Epoch int64  `json:"epoch"`
		// Approval is the approval the decision rests on (HR-038), checked
		// against the pinned approver keys before BeginDispatch.
		Approval *proof.Approval `json:"approval,omitzero"`
	} `json:"pap"`
}

// permitWant is what the permit must bind (HR-009).
type permitWant struct {
	PermitID, Txn, Act string
	Epoch              int64
}

// permitVerifier checks dispatch permits against the Authority's JWKS.
type permitVerifier struct {
	jwksURL   string
	client    *http.Client
	gatewayID string
	org       string
	now       func() time.Time

	mu      sync.Mutex
	v       *jws.Verifier
	kids    map[string]bool
	fetched time.Time
}

func newPermitVerifier(jwksURL string, client *http.Client, gatewayID, org string) *permitVerifier {
	return &permitVerifier{jwksURL: jwksURL, client: client, gatewayID: gatewayID, org: org, now: time.Now}
}

// verify checks the signature, typ, audience, expiry and every binding,
// and returns the approval the permit carries, if any.
func (pv *permitVerifier) verify(ctx context.Context, token string, want permitWant) (*proof.Approval, error) {
	v, err := pv.verifierFor(ctx, token)
	if err != nil {
		return nil, err
	}
	payload, _, err := v.Verify(token)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPermitInvalid, err)
	}
	var c permitClaims
	if err := json.Unmarshal(payload, &c, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("%w: claims: %w", ErrPermitInvalid, err)
	}
	now := pv.now().Unix()
	switch {
	case c.Aud != "gw:"+pv.gatewayID:
		return nil, fmt.Errorf("%w: audience %q", ErrPermitInvalid, c.Aud)
	case now >= c.Exp:
		return nil, fmt.Errorf("%w: expired", ErrPermitInvalid)
	case c.Iat > now+2: // small skew between gateway and Authority clocks
		return nil, fmt.Errorf("%w: issued in the future", ErrPermitInvalid)
	case c.Pap.V != 1 || c.Pap.Org != pv.org:
		return nil, fmt.Errorf("%w: wrong version or org", ErrPermitInvalid)
	case c.Jti != want.PermitID || c.Pap.Txn != want.Txn:
		return nil, fmt.Errorf("%w: permit or transaction id mismatch", ErrPermitInvalid)
	case c.Pap.Act != want.Act:
		return nil, fmt.Errorf("%w: action hash mismatch", ErrPermitInvalid)
	case c.Pap.Epoch <= 0 || c.Pap.Epoch != want.Epoch:
		return nil, fmt.Errorf("%w: epoch mismatch", ErrPermitInvalid)
	}
	return c.Pap.Approval, nil
}

// verifierFor returns a verifier that knows the token's kid, refetching the
// JWKS (rate-limited) when the kid is new, for example after a rotation.
func (pv *permitVerifier) verifierFor(ctx context.Context, token string) (*jws.Verifier, error) {
	kid, _, err := jws.Unverified(token)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPermitInvalid, err)
	}
	pv.mu.Lock()
	defer pv.mu.Unlock()
	if pv.v != nil && (pv.kids[kid] || pv.now().Sub(pv.fetched) < jwksRefreshEvery) {
		return pv.v, nil
	}
	if err := pv.fetchLocked(ctx); err != nil {
		if pv.v != nil {
			return pv.v, nil
		}
		return nil, err
	}
	return pv.v, nil
}

func (pv *permitVerifier) fetchLocked(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pv.jwksURL, nil)
	if err != nil {
		return err
	}
	resp, err := pv.client.Do(req)
	if err != nil {
		return fmt.Errorf("gateway: fetch JWKS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("gateway: fetch JWKS: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return fmt.Errorf("gateway: read JWKS: %w", err)
	}
	var set struct {
		Keys []jws.JWK `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		return fmt.Errorf("gateway: parse JWKS: %w", err)
	}
	// Only permit keys whose kid matches their own thumbprint: a receipts or
	// workload-token key can never verify a permit.
	pubs := map[string]ed25519.PublicKey{}
	for _, k := range set.Keys {
		pub, err := k.Key()
		if err != nil || !strings.HasPrefix(k.Kid, string(keys.PurposePermits)+"-") || k.Kid != keys.KIDFor(keys.PurposePermits, pub) {
			continue
		}
		pubs[k.Kid] = pub
	}
	v, err := jws.NewVerifier(permitType, pubs)
	if err != nil {
		return err
	}
	pv.v = v
	pv.kids = map[string]bool{}
	for kid := range pubs {
		pv.kids[kid] = true
	}
	pv.fetched = pv.now()
	return nil
}
