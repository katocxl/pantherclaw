// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package inbound holds the pure checks of a signed inbound automation
// event (G0 M11 part 2 D21, HR-275, T-122): the Standard Webhooks headers,
// the HMAC-SHA256 signature against the current secret or the previous one
// during a rotation overlap, the timestamp window and the event body. The
// endpoint applies them in the order D21 fixes; nothing here touches the
// database or stores a body.
package inbound

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	ndomain "github.com/katocxl/pantherclaw/internal/notifications/domain"
)

// Standard Webhooks headers.
const (
	HeaderID        = "webhook-id"
	HeaderTimestamp = "webhook-timestamp"
	HeaderSignature = "webhook-signature"
)

// Limits (HR-275).
const (
	// MaxBody is the largest accepted body.
	MaxBody = 64 << 10
	// Tolerance is how far a timestamp may be from the server's clock.
	Tolerance = 5 * time.Minute
	// ReplayWindow is how long a webhook-id is remembered.
	ReplayWindow = 7 * 24 * time.Hour
	// RotationOverlap is the longest the previous secret stays valid.
	RotationOverlap = 24 * time.Hour
	// MaxIDLen bounds a webhook-id.
	MaxIDLen = 256
	// MaxSignatures bounds the signatures one request may carry.
	MaxSignatures = 8
	// MaxSignatureHeader bounds the webhook-signature header.
	MaxSignatureHeader = 1024
	// MaxTypeLen bounds an event type.
	MaxTypeLen = 100
	// MaxTypes bounds the types a source declares.
	MaxTypes = 20
)

// Errors. The endpoint maps them to statuses: headers 400, signature and
// timestamp 401, body and type 422.
var (
	ErrHeaders   = errors.New("inbound: Standard Webhooks headers missing or malformed")
	ErrSignature = errors.New("inbound: no valid signature")
	ErrStale     = errors.New("inbound: timestamp outside the accepted window")
	ErrBody      = errors.New("inbound: the body is not a JSON object with a string type")
	ErrType      = errors.New("inbound: the source does not declare this event type")
)

// Headers are a request's Standard Webhooks headers.
type Headers struct {
	ID        string
	Timestamp int64
	Signature string
}

// ReadHeaders reads and bounds the three headers. A webhook-id is 1–256
// printable ASCII characters; a timestamp is whole Unix seconds.
func ReadHeaders(h http.Header) (Headers, error) {
	id, ts, sig := h.Values(HeaderID), h.Values(HeaderTimestamp), h.Values(HeaderSignature)
	if len(id) != 1 || len(ts) != 1 || len(sig) != 1 {
		return Headers{}, ErrHeaders
	}
	if !printableASCII(id[0], MaxIDLen) || sig[0] == "" || len(sig[0]) > MaxSignatureHeader {
		return Headers{}, ErrHeaders
	}
	if ts[0] == "" || len(ts[0]) > 12 || strings.TrimLeft(ts[0], "0123456789") != "" {
		return Headers{}, ErrHeaders
	}
	n, err := strconv.ParseInt(ts[0], 10, 64)
	if err != nil {
		return Headers{}, ErrHeaders
	}
	return Headers{ID: id[0], Timestamp: n, Signature: sig[0]}, nil
}

func printableASCII(s string, maxLen int) bool {
	if s == "" || len(s) > maxLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// Secrets returns the secrets a signature may match at now: the current
// one, and the previous one until prevUntil (set at rotation to at most
// RotationOverlap later).
func Secrets(current, previous []byte, prevUntil, now time.Time) [][]byte {
	out := [][]byte{current}
	if len(previous) > 0 && now.Before(prevUntil) {
		out = append(out, previous)
	}
	return out
}

// VerifySignature reports whether any v1 signature in the header matches
// any of secrets over "id.timestamp.body". Every comparison runs, in
// constant time, whatever matched earlier; other signature versions are
// ignored, and more than MaxSignatures entries are refused.
func VerifySignature(secrets [][]byte, h Headers, body []byte) error {
	entries := strings.Fields(h.Signature)
	if len(entries) == 0 || len(entries) > MaxSignatures {
		return ErrSignature
	}
	want := make([][]byte, 0, len(secrets))
	for _, s := range secrets {
		if len(s) == 0 {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(ndomain.Sign(s, h.ID, h.Timestamp, body), "v1,"))
		if err != nil {
			return ErrSignature
		}
		want = append(want, raw)
	}
	ok := 0
	for _, e := range entries {
		ver, b64, found := strings.Cut(e, ",")
		if !found || ver != "v1" {
			continue
		}
		got, err := base64.StdEncoding.DecodeString(b64)
		if err != nil || len(got) != sha256.Size {
			continue
		}
		for _, w := range want {
			if hmac.Equal(got, w) {
				ok++
			}
		}
	}
	if ok == 0 {
		return ErrSignature
	}
	return nil
}

// CheckTimestamp refuses a timestamp more than Tolerance from now, either
// way.
func CheckTimestamp(ts int64, now time.Time) error {
	d := now.Sub(time.Unix(ts, 0))
	if d > Tolerance || d < -Tolerance {
		return ErrStale
	}
	return nil
}

// Event is what the endpoint reads from a body: its type. The body itself
// is never stored; parameters are read from it with JSON Pointers.
type Event struct {
	Type string
}

// ParseEvent requires a JSON object (RFC 7493: UTF-8, unique names) of at
// most MaxBody bytes whose "type" is a string the source declares.
func ParseEvent(body []byte, types []string) (Event, error) {
	if len(body) == 0 || len(body) > MaxBody {
		return Event{}, ErrBody
	}
	var members map[string]jsontext.Value
	if err := json.Unmarshal(body, &members); err != nil || members == nil {
		return Event{}, ErrBody
	}
	raw, ok := members["type"]
	if !ok || raw.Kind() != '"' {
		return Event{}, ErrBody
	}
	var typ string
	if err := json.Unmarshal(raw, &typ); err != nil || typ == "" || utf8.RuneCountInString(typ) > MaxTypeLen {
		return Event{}, ErrBody
	}
	if !slices.Contains(types, typ) {
		return Event{}, ErrType
	}
	return Event{Type: typ}, nil
}

// Digest is the SHA-256 of a body, recorded with the receipt and the audit
// record instead of the body.
func Digest(body []byte) [sha256.Size]byte { return sha256.Sum256(body) }
