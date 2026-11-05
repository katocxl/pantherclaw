// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/v2"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	idapp "github.com/katocxl/pantherclaw/internal/idaccess/app"
	iddomain "github.com/katocxl/pantherclaw/internal/idaccess/domain"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
)

// The M30 range support (G0 M30): the share scenario's grant, and the
// bound MCP token attacks of idp.probe.

// shareScenario is the scenario whose run holds a grant of the two pc.github
// operations that share a repository (G0 M30 D934): the seeded grant names
// neither.
const shareScenario = "RT-201"

// configScenario is the scenario whose stack seeds pc.shell and the hook
// connection "shell", for writes to agent configuration (G0 M30 D943).
const configScenario = "RT-203"

// shareBounds is that grant.
const shareBounds = `{"operations": ["github.repo.visibility.update", "github.repo.transfer"]}`

// dpopProof signs a token endpoint DPoP proof for htu with key (RFC 9449
// §4.2: no ath, no nonce).
func dpopProof(t *testing.T, key ed25519.PrivateKey, htu string) string {
	t.Helper()
	var id [16]byte
	_, _ = rand.Read(id[:])
	payload, err := json.Marshal(map[string]any{"htm": "POST", "htu": htu, "iat": time.Now().Unix(), "jti": base64.RawURLEncoding.EncodeToString(id[:])})
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := key.Public().(ed25519.PublicKey)
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: key}, &jose.SignerOptions{ExtraHeaders: map[jose.HeaderKey]any{
		"typ": pap.DPoPType, "jwk": map[string]string{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	obj, err := s.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	c, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// boundToken is an MCP access token the jwt-bearer grant binds to a fresh
// DPoP key (G0 M30 D912).
func (a *idpAccess) boundToken(t *testing.T) (string, error) {
	t.Helper()
	key, _ := strangerKey(t)
	ctx := authnapp.WithDPoP(context.Background(), []string{dpopProof(t, key, strings.TrimSuffix(a.s.apiURL, "/")+authnapp.TokenPath)})
	res, err := a.ex.JWTBearer(ctx, url.Values{
		"grant_type": {idapp.GrantJWTBearer}, "assertion": {a.assert(t, idpPerson, idpClientID)},
		"client_assertion_type": {authnapp.AssertionType}, "client_assertion": {a.clientAssertion(t, idpClientID, a.s.key, a.kid)},
	})
	if err != nil {
		return "", err
	}
	if res.TokenType != "DPoP" {
		return "", fmt.Errorf("a token request with a proof got token_type %q", res.TokenType)
	}
	return res.AccessToken, nil
}

// idpProbeM30 runs the bound-token attacks of idp.probe (G0 M30 D913,
// HR-700; RT-202): a bound token sent as a bearer token, and under the DPoP
// scheme with no proof. Both are refused; ok is false for another attack.
func (d *rangeDriver) idpProbeM30(a *idpAccess, attack string) (domain.Observation, bool, error) {
	t := d.t
	var scheme string
	switch attack {
	case "bound_token_as_bearer":
		scheme = "Bearer "
	case "bound_token_without_proof":
		scheme = "DPoP "
	default:
		return domain.Observation{}, false, nil
	}
	tok, err := a.boundToken(t)
	if err != nil {
		return domain.Observation{}, true, fmt.Errorf("a bound token: %w", err)
	}
	status, challenge, body := a.call(t, iddomain.ResourcePath+idpConnection, idpRefund("9.00"), map[string]string{"Authorization": scheme + tok})
	return idpCall(status, challenge, body), true, nil
}
