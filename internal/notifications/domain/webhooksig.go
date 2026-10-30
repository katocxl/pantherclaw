// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// SignatureScheme is how a destination's webhooks are signed (G0 M20
// D251): every destination sends the HMAC `v1,` signatures; one that opts
// in also sends a `v1a,` Ed25519 signature (HR-510). The notification
// channels, SIEM destinations and automation endpoint destinations share
// it.
type SignatureScheme string

// Signature schemes.
const (
	SchemeHMAC        SignatureScheme = "hmac" // the default
	SchemeHMACEd25519 SignatureScheme = "hmac+ed25519"
)

// Valid reports whether s is a known scheme.
func (s SignatureScheme) Valid() bool { return s == SchemeHMAC || s == SchemeHMACEd25519 }

// Ed25519 reports whether s sends the `v1a,` signature.
func (s SignatureScheme) Ed25519() bool { return s == SchemeHMACEd25519 }

// WebhookSigner signs webhook content with an organization's ACTIVE
// `webhooks` key, and with no other organization's key (HR-511). The
// keystore implements it.
type WebhookSigner interface {
	SignWebhook(ctx context.Context, org ids.OrgID, content []byte) ([]byte, error)
}

// WebhookKeys is the signer plus what an opt-in needs: EnsureWebhookKey
// returns the kid of the org's ACTIVE webhooks key, creating it when the
// org has none, so the JWKS lists it before the first signed delivery.
type WebhookKeys interface {
	WebhookSigner
	EnsureWebhookKey(ctx context.Context, org ids.OrgID) (kid string, err error)
}

// WebhookJWKSPath is where an org's webhook JWKS is served (D251): its
// ACTIVE and RETIRING webhooks keys, and no other org's (HR-511).
func WebhookJWKSPath(org ids.OrgID) string {
	return "/.well-known/pantherclaw/orgs/" + org.String() + "/webhook-jwks.json"
}

// WebhookJWKSURL is the org's webhook JWKS under publicURL.
func WebhookJWKSURL(publicURL string, org ids.OrgID) string {
	return strings.TrimSuffix(publicURL, "/") + WebhookJWKSPath(org)
}

// ErrNoWebhookSigner reports an opted-in destination with no signer wired:
// its delivery fails rather than going out without the signature its
// receiver may require.
var ErrNoWebhookSigner = errors.New("notifications: no webhook signing key")

// SignedContent is what both schemes sign (Standard Webhooks):
// "msgID.timestamp.body".
func SignedContent(msgID string, timestamp int64, body []byte) []byte {
	ts := strconv.FormatInt(timestamp, 10)
	b := make([]byte, 0, len(msgID)+len(ts)+len(body)+2)
	b = append(b, msgID...)
	b = append(b, '.')
	b = append(b, ts...)
	b = append(b, '.')
	return append(b, body...)
}

// V1a formats an Ed25519 signature the way Standard Webhooks sends it.
func V1a(sig []byte) string { return "v1a," + base64.StdEncoding.EncodeToString(sig) }

// VerifyV1a reports whether value is a `v1a,` signature of the content by
// pub (receivers do this with a key from the org's JWKS).
func VerifyV1a(pub ed25519.PublicKey, value string, msgID string, timestamp int64, body []byte) bool {
	const prefix = "v1a,"
	if len(value) <= len(prefix) || value[:len(prefix)] != prefix || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(value[len(prefix):])
	return err == nil && ed25519.Verify(pub, SignedContent(msgID, timestamp, body), sig)
}

// SignatureHeader returns the webhook-signature header value of one
// message for a destination of org: the HMAC `v1,` signatures of secrets
// (current first) always, then, for an opted-in destination, the `v1a,`
// signature by the org's webhooks key (HR-510). A signing failure is
// returned, never a header without the signature the destination asked
// for.
func SignatureHeader(ctx context.Context, signer WebhookSigner, org ids.OrgID, scheme SignatureScheme,
	secrets [][]byte, msgID string, timestamp int64, body []byte,
) (string, error) {
	h := Signatures(secrets, msgID, timestamp, body)
	if !scheme.Ed25519() {
		return h, nil
	}
	if signer == nil {
		return "", ErrNoWebhookSigner
	}
	sig, err := signer.SignWebhook(ctx, org, SignedContent(msgID, timestamp, body))
	if err != nil {
		return "", err
	}
	if len(sig) != ed25519.SignatureSize {
		return "", ErrNoWebhookSigner
	}
	return h + " " + V1a(sig), nil
}
