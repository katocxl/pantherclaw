// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package inbound

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	ndomain "github.com/katocxl/pantherclaw/internal/notifications/domain"
)

func headers(id, ts, sig string) http.Header {
	h := http.Header{}
	if id != "" {
		h.Set(HeaderID, id)
	}
	if ts != "" {
		h.Set(HeaderTimestamp, ts)
	}
	if sig != "" {
		h.Set(HeaderSignature, sig)
	}
	return h
}

// The Standard Webhooks reference vector.
func TestStandardWebhooksVector(t *testing.T) {
	t.Parallel()
	secret, err := base64.StdEncoding.DecodeString("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw")
	if err != nil {
		t.Fatal(err)
	}
	h := Headers{ID: "msg_p5jXN8AQM9LWM0D4loKWxJek", Timestamp: 1614265330, Signature: "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE="}
	if err := VerifySignature([][]byte{secret}, h, []byte(`{"test": 2432232314}`)); err != nil {
		t.Fatalf("reference vector: %v", err)
	}
	if err := VerifySignature([][]byte{secret}, h, []byte(`{"test": 2432232315}`)); !errors.Is(err, ErrSignature) {
		t.Fatalf("changed body verified: %v", err)
	}
}

func TestReadHeaders(t *testing.T) {
	t.Parallel()
	got, err := ReadHeaders(headers("msg_1", "1614265330", "v1,abc"))
	if err != nil || got != (Headers{ID: "msg_1", Timestamp: 1614265330, Signature: "v1,abc"}) {
		t.Fatalf("got %+v %v", got, err)
	}
	for name, h := range map[string]http.Header{
		"no id":          headers("", "1", "v1,a"),
		"no timestamp":   headers("m", "", "v1,a"),
		"no signature":   headers("m", "1", ""),
		"space in id":    headers("m 1", "1", "v1,a"),
		"non-ascii id":   headers("mé", "1", "v1,a"),
		"long id":        headers(strings.Repeat("m", MaxIDLen+1), "1", "v1,a"),
		"signed ts":      headers("m", "-1", "v1,a"),
		"plus ts":        headers("m", "+1", "v1,a"),
		"fraction ts":    headers("m", "1.5", "v1,a"),
		"huge ts":        headers("m", "9999999999999", "v1,a"),
		"long signature": headers("m", "1", strings.Repeat("a", MaxSignatureHeader+1)),
	} {
		if _, err := ReadHeaders(h); !errors.Is(err, ErrHeaders) {
			t.Errorf("%s: %v", name, err)
		}
	}
	dup := headers("m", "1", "v1,a")
	dup.Add(HeaderID, "n")
	if _, err := ReadHeaders(dup); !errors.Is(err, ErrHeaders) {
		t.Errorf("two ids: %v", err)
	}
}

func TestVerifySignature(t *testing.T) {
	t.Parallel()
	cur, _ := ndomain.NewSigningSecret()
	prev, _ := ndomain.NewSigningSecret()
	other, _ := ndomain.NewSigningSecret()
	body := []byte(`{"type":"ticket.created","id":"T-1"}`)
	const id, ts = "msg_1", int64(1_800_000_000)
	sign := func(s []byte) string { return ndomain.Sign(s, id, ts, body) }
	ok := func(sig string, secrets ...[]byte) error {
		return VerifySignature(secrets, Headers{ID: id, Timestamp: ts, Signature: sig}, body)
	}

	if err := ok(sign(cur), cur); err != nil {
		t.Errorf("current: %v", err)
	}
	if err := ok(sign(prev), cur, prev); err != nil {
		t.Errorf("previous during overlap: %v", err)
	}
	if err := ok(sign(prev), cur); !errors.Is(err, ErrSignature) {
		t.Errorf("previous after overlap: %v", err)
	}
	if err := ok(sign(other)+" "+sign(cur), cur); err != nil {
		t.Errorf("one of several: %v", err)
	}
	if err := ok(ndomain.Signatures([][]byte{cur, prev}, id, ts, body), cur); err != nil {
		t.Errorf("the sender's overlap header: %v", err)
	}
	for name, sig := range map[string]string{
		"wrong secret":   sign(other),
		"other version":  "v1a," + strings.TrimPrefix(sign(cur), "v1,"),
		"no version":     strings.TrimPrefix(sign(cur), "v1,"),
		"bad base64":     "v1,!!!",
		"short mac":      "v1," + base64.StdEncoding.EncodeToString([]byte("short")),
		"too many":       strings.Repeat(sign(other)+" ", MaxSignatures) + sign(cur),
		"empty":          " ",
		"other id":       ndomain.Sign(cur, "msg_2", ts, body),
		"other time":     ndomain.Sign(cur, id, ts+1, body),
		"other body":     ndomain.Sign(cur, id, ts, []byte(`{}`)),
		"id/ts confused": ndomain.Sign(cur, id+".1", 800_000_000, body),
	} {
		if err := ok(sig, cur, prev); !errors.Is(err, ErrSignature) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// No secret, or an empty one, never verifies.
	if err := ok(ndomain.Sign(nil, id, ts, body)); !errors.Is(err, ErrSignature) {
		t.Errorf("no secrets: %v", err)
	}
	if err := ok(ndomain.Sign([]byte{}, id, ts, body), []byte{}); !errors.Is(err, ErrSignature) {
		t.Errorf("empty secret: %v", err)
	}
}

func TestSecrets(t *testing.T) {
	t.Parallel()
	now := time.Date(2027, 1, 1, 12, 0, 0, 0, time.UTC)
	cur, prev := []byte("c"), []byte("p")
	if got := Secrets(cur, prev, now.Add(time.Hour), now); len(got) != 2 {
		t.Errorf("overlap: %d secrets", len(got))
	}
	if got := Secrets(cur, prev, now, now); len(got) != 1 {
		t.Errorf("overlap ended: %d secrets", len(got))
	}
	if got := Secrets(cur, nil, now.Add(time.Hour), now); len(got) != 1 {
		t.Errorf("no previous: %d secrets", len(got))
	}
}

func TestCheckTimestamp(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_800_000_000, 0)
	for _, d := range []time.Duration{0, Tolerance, -Tolerance, time.Minute} {
		if err := CheckTimestamp(now.Add(d).Unix(), now); err != nil {
			t.Errorf("%v: %v", d, err)
		}
	}
	for _, d := range []time.Duration{Tolerance + time.Second, -Tolerance - time.Second, 24 * time.Hour} {
		if err := CheckTimestamp(now.Add(d).Unix(), now); !errors.Is(err, ErrStale) {
			t.Errorf("%v: %v", d, err)
		}
	}
	if err := CheckTimestamp(0, now); !errors.Is(err, ErrStale) {
		t.Errorf("epoch: %v", err)
	}
}

func TestParseEvent(t *testing.T) {
	t.Parallel()
	types := []string{"ticket.created", "ticket.closed"}
	ev, err := ParseEvent([]byte(`{"type":"ticket.created","data":{"id":"T-1"}}`), types)
	if err != nil || ev.Type != "ticket.created" {
		t.Fatalf("got %+v %v", ev, err)
	}
	for name, body := range map[string]string{
		"empty":           ``,
		"null":            `null`,
		"array":           `[{"type":"ticket.created"}]`,
		"no type":         `{"kind":"ticket.created"}`,
		"number type":     `{"type":1}`,
		"empty type":      `{"type":""}`,
		"duplicate type":  `{"type":"ticket.closed","type":"ticket.created"}`,
		"invalid utf-8":   "{\"type\":\"ticket.created\",\"x\":\"\xff\"}",
		"trailing":        `{"type":"ticket.created"} {}`,
		"long type":       `{"type":"` + strings.Repeat("t", MaxTypeLen+1) + `"}`,
		"oversize":        `{"type":"ticket.created","pad":"` + strings.Repeat("a", MaxBody) + `"}`,
		"broken":          `{"type":"ticket.created"`,
		"lone surrogate":  `{"type":"\ud800"}`,
		"nested type":     `{"data":{"type":"ticket.created"}}`,
		"case of key":     `{"Type":"ticket.created"}`,
		"type in escapes": "{\"t\x5cu0079pe\":\"ticket.created\",\"type\":5}", // "type" spelled with an escape
	} {
		if _, err := ParseEvent([]byte(body), types); !errors.Is(err, ErrBody) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := ParseEvent([]byte(`{"type":"ticket.deleted"}`), types); !errors.Is(err, ErrType) {
		t.Errorf("undeclared type: %v", err)
	}
	if _, err := ParseEvent([]byte(`{"type":"TICKET.CREATED"}`), types); !errors.Is(err, ErrType) {
		t.Errorf("types are exact: %v", err)
	}
}

func TestDigest(t *testing.T) {
	t.Parallel()
	a, b := Digest([]byte("x")), Digest([]byte("y"))
	if a == b || strconv.Itoa(len(a)) != "32" {
		t.Fatal("digest")
	}
}
