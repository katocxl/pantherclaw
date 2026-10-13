// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"strconv"
	"strings"
)

// MaxURL bounds a destination URL.
const MaxURL = 2048

// SlackHost is the only host a Slack channel may post to (incoming
// webhooks): a Slack channel is never a generic HTTP client (HR-157).
const SlackHost = "hooks.slack.com"

// Destination errors.
var (
	ErrBadURL     = errors.New("notifications: the URL must be https, without credentials, query-safe and public")
	ErrOwnHost    = errors.New("notifications: a channel cannot point at PantherClaw itself")
	ErrPrivateURL = errors.New("notifications: private and loopback addresses are not allowed")
	ErrSlackURL   = errors.New("notifications: a Slack channel needs an https://hooks.slack.com/services/... URL")
)

// CheckWebhookURL validates a webhook destination when a channel is saved
// (HR-157): https only, no userinfo or fragment, port 443 or 1024-65535,
// never PantherClaw's own host, and not a host the egress guard denies as
// written. denied is that guard's reading of the host (httpx.DeniedHost
// with the operator-allowed ranges): an IP address in any spelling a
// resolver accepts (decimal, octal or hex IPv4, IPv4-mapped IPv6) must be
// public unless such a range covers it, and a metadata service is refused
// by address or name even then. Names are checked again at dial time by the
// egress client, which also blocks DNS rebinding.
func CheckWebhookURL(raw, ownHost string, denied func(host string) bool) error {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > MaxURL || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" ||
		u.Opaque != "" || strings.ContainsAny(raw, " \t\r\n\\") {
		return ErrBadURL
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || (n != 443 && (n < 1024 || n > 65535)) {
			return ErrBadURL
		}
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return ErrPrivateURL
	}
	if own := strings.TrimSuffix(strings.ToLower(ownHost), "."); own != "" && host == own {
		return ErrOwnHost
	}
	if denied(host) {
		return ErrPrivateURL
	}
	return nil
}

// CheckSlackURL validates a Slack incoming-webhook URL.
func CheckSlackURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > MaxURL || u.Scheme != "https" || u.Hostname() != SlackHost || (u.Port() != "" && u.Port() != "443") ||
		u.User != nil || u.RawQuery != "" || u.Fragment != "" || !strings.HasPrefix(u.Path, "/services/") ||
		strings.Contains(u.Path, "..") || strings.ContainsAny(raw, " \t\r\n\\") {
		return ErrSlackURL
	}
	return nil
}

// Standard Webhooks (https://www.standardwebhooks.com) v1 signatures.

// SecretPrefix marks a webhook signing secret when shown.
const SecretPrefix = "whsec_"

// NewSigningSecret returns 32 random bytes.
func NewSigningSecret() ([]byte, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// FormatSecret shows a signing secret the way receivers expect it.
func FormatSecret(secret []byte) string {
	return SecretPrefix + base64.StdEncoding.EncodeToString(secret)
}

// Sign returns the v1 signature of one message: "v1," followed by the
// base64 HMAC-SHA256 over "msgID.timestamp.body".
func Sign(secret []byte, msgID string, timestamp int64, body []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(msgID))
	m.Write([]byte{'.'})
	m.Write([]byte(strconv.FormatInt(timestamp, 10)))
	m.Write([]byte{'.'})
	m.Write(body)
	return "v1," + base64.StdEncoding.EncodeToString(m.Sum(nil))
}

// Signatures returns the webhook-signature header value: one signature per
// secret (current first), space-separated while a rotated secret overlaps.
func Signatures(secrets [][]byte, msgID string, timestamp int64, body []byte) string {
	out := make([]string, 0, len(secrets))
	for _, s := range secrets {
		out = append(out, Sign(s, msgID, timestamp, body))
	}
	return strings.Join(out, " ")
}
