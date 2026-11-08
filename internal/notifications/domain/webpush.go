// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json/v2"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"time"
)

// Web Push (G0 M36 D1066; HR-793): a push carries a title and a link only.
// The payload is encrypted for the browser with RFC 8291 (aes128gcm,
// RFC 8188) and the request is signed with the deployment's VAPID key
// (RFC 8292, ES256). Pure functions; the app sends.

// Push request headers.
const (
	// PushTTL is how long a push service keeps an undelivered push.
	PushTTL = 3600
	// PushUrgency asks the push service to deliver at once.
	PushUrgency = "high"
	// vapidLifetime is the lifetime of one VAPID JWT (RFC 8292 §2 allows up
	// to 24 hours).
	vapidLifetime = 12 * time.Hour
	// pushRecordSize is the aes128gcm record size: one record holds the
	// whole link-only payload.
	pushRecordSize = 4096
	// MaxPushPayload bounds the plaintext of one push.
	MaxPushPayload = 1024
)

// PushServiceHosts are the push services a subscription's endpoint may be
// on: the host itself or a subdomain of one.
var PushServiceHosts = []string{
	"fcm.googleapis.com", "updates.push.services.mozilla.com", "notify.windows.com", "web.push.apple.com",
}

// Errors of Web Push input.
var (
	ErrPushEndpoint = errors.New("notifications: the push endpoint is not https on an allowed push service")
	ErrPushKeys     = errors.New("notifications: the subscription keys are not a P-256 key and a 16-byte secret")
)

// PushEndpointHost checks a subscription endpoint: an absolute https URL
// without user info or a port other than 443, on an allowed push service.
// It returns the host.
func PushEndpointHost(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Host == "" || u.Fragment != "" {
		return "", ErrPushEndpoint
	}
	if p := u.Port(); p != "" && p != "443" {
		return "", ErrPushEndpoint
	}
	host := strings.ToLower(u.Hostname())
	for _, h := range PushServiceHosts {
		if host == h || strings.HasSuffix(host, "."+h) {
			return host, nil
		}
	}
	return "", ErrPushEndpoint
}

// PushKeys decodes a subscription's keys.p256dh (an uncompressed P-256
// point) and keys.auth (16 bytes), base64url with or without padding.
func PushKeys(p256dh, auth string) (public, secret []byte, err error) {
	public, err1 := b64(p256dh)
	secret, err2 := b64(auth)
	if err1 != nil || err2 != nil || len(secret) != 16 {
		return nil, nil, ErrPushKeys
	}
	if _, err := ecdh.P256().NewPublicKey(public); err != nil {
		return nil, nil, ErrPushKeys
	}
	return public, secret, nil
}

func b64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

// PushPayload is everything a push carries (HR-793): a fixed title and a
// link to the approval page. Never an operation, an agent, a parameter or
// a note.
type PushPayload struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

// EncryptPush encrypts plaintext for a subscription (RFC 8291 §3): an
// ephemeral ECDH key, the auth secret mixed in, and one aes128gcm record
// (RFC 8188) with the ephemeral public key as its key id.
func EncryptPush(plaintext, uaPublic, authSecret []byte) ([]byte, error) {
	if len(plaintext) > MaxPushPayload {
		return nil, errors.New("notifications: push payload too large")
	}
	ua, err := ecdh.P256().NewPublicKey(uaPublic)
	if err != nil || len(authSecret) != 16 {
		return nil, ErrPushKeys
	}
	as, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := as.ECDH(ua)
	if err != nil {
		return nil, err
	}
	asPublic := as.PublicKey().Bytes()
	// IKM = HKDF(auth_secret, ecdh_secret, "WebPush: info" 0x00 ua_public as_public, 32).
	info := append(append([]byte("WebPush: info\x00"), uaPublic...), asPublic...)
	ikm, err := hkdf.Key(sha256.New, shared, authSecret, string(info), 32)
	if err != nil {
		return nil, err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	prk, err := hkdf.Extract(sha256.New, ikm, salt)
	if err != nil {
		return nil, err
	}
	cek, err := hkdf.Expand(sha256.New, prk, "Content-Encoding: aes128gcm\x00", 16)
	if err != nil {
		return nil, err
	}
	nonce, err := hkdf.Expand(sha256.New, prk, "Content-Encoding: nonce\x00", 12)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// The single (and so last) record ends with the 0x02 delimiter.
	record := append(append([]byte{}, plaintext...), 0x02)
	header := make([]byte, 0, 16+4+1+len(asPublic))
	header = append(header, salt...)
	header = binary.BigEndian.AppendUint32(header, pushRecordSize)
	header = append(header, byte(len(asPublic)))
	header = append(header, asPublic...)
	return gcm.Seal(header, nonce, record, nil), nil
}

// VAPIDAuthorization returns the Authorization header of a push request
// (RFC 8292 §3): "vapid t=<ES256 JWT>, k=<public key>". The JWT's audience
// is the endpoint's origin, its subject the deployment's contact (a mailto:
// or https URL), and it expires within 12 hours.
func VAPIDAuthorization(signer crypto.Signer, endpoint, subject string, now time.Time) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", ErrPushEndpoint
	}
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		return "", errors.New("notifications: the VAPID key is not an ECDSA key")
	}
	ek, err := pub.ECDH()
	if err != nil {
		return "", err
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"JWT","alg":"ES256"}`))
	claims, err := json.Marshal(struct {
		Aud string `json:"aud"`
		Exp int64  `json:"exp"`
		Sub string `json:"sub"`
	}{Aud: u.Scheme + "://" + u.Host, Exp: now.Add(vapidLifetime).Unix(), Sub: subject})
	if err != nil {
		return "", err
	}
	input := header + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(input))
	der, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return "", err
	}
	var sig struct{ R, S *big.Int }
	if rest, err := asn1.Unmarshal(der, &sig); err != nil || len(rest) != 0 {
		return "", errors.New("notifications: malformed VAPID signature")
	}
	raw := make([]byte, 64)
	sig.R.FillBytes(raw[:32])
	sig.S.FillBytes(raw[32:])
	return "vapid t=" + input + "." + base64.RawURLEncoding.EncodeToString(raw) +
		", k=" + base64.RawURLEncoding.EncodeToString(ek.Bytes()), nil
}

// VAPIDPublicKey is the applicationServerKey of a VAPID key: its
// uncompressed P-256 point, base64url without padding.
func VAPIDPublicKey(pub crypto.PublicKey) (string, error) {
	k, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return "", errors.New("notifications: the VAPID key is not an ECDSA key")
	}
	ek, err := k.ECDH()
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(ek.Bytes()), nil
}
