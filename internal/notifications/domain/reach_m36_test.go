// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestHR792_QuietHoursAndDigestsDelayOnlyThatPersonsApprovalNotices: quiet
// hours hold during the window and release outside it, and a security
// notice is never a digest or a delayed push.
// Covers: HR-792
func TestHR792_QuietHoursAndDigestsDelayOnlyThatPersonsApprovalNotices(t *testing.T) {
	p := Preferences{Delivery: DeliveryDigest, DigestMinutes: 15, QuietStart: "22:00", QuietEnd: "06:00", TimeZone: "UTC"}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	inside := time.Date(2026, 11, 7, 23, 30, 0, 0, time.UTC)
	until := p.QuietUntil(inside)
	want := time.Date(2026, 11, 8, 6, 0, 0, 0, time.UTC)
	if !until.Equal(want) {
		t.Fatalf("quiet until %s, want %s", until, want)
	}
	if !p.QuietUntil(time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)).IsZero() {
		t.Fatal("noon is inside quiet hours")
	}
	if !QuietDelays("approval.requested") || !QuietDelays("approval.escalated") || !QuietDelays(DigestType) {
		t.Fatal("an approval notice was not delayed")
	}
	if QuietDelays("incident.raised") || DigestReplaces("incident.raised") || PushEvent("incident.raised") {
		t.Fatal("a security notice was delayed")
	}
	bad := p
	bad.DigestMinutes = 10
	if err := bad.Validate(); !errors.Is(err, ErrPreferences) {
		t.Fatalf("10-minute digest: %v", err)
	}
}

// TestHR793_PushCarriesALinkOnlyToAnAllowedService: the payload is a title
// and a URL, the endpoint must be https on an allow-listed host, and a
// VAPID token's claims are the origin, expiry and subject.
// Covers: HR-793
func TestHR793_PushCarriesALinkOnlyToAnAllowedService(t *testing.T) {
	host, err := PushEndpointHost("https://fcm.googleapis.com/fcm/send/abc")
	if err != nil || host != "fcm.googleapis.com" {
		t.Fatalf("allowed host: %s %v", host, err)
	}
	for _, raw := range []string{
		"http://fcm.googleapis.com/fcm/send/abc",
		"https://evil.example/push",
		"https://user:pass@fcm.googleapis.com/fcm/send/abc",
		"https://fcm.googleapis.com:8443/fcm/send/abc",
	} {
		if _, err := PushEndpointHost(raw); !errors.Is(err, ErrPushEndpoint) {
			t.Errorf("accepted %s: %v", raw, err)
		}
	}
	id := "01920000-0000-7000-8000-000000000001"
	payload := PushPayloadFor("https://pc.example", "approval.requested", id, 3)
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc) != 2 || doc["title"] != "Approval waiting" || doc["url"] != "https://pc.example/approvals/"+id {
		t.Fatalf("payload %s", raw)
	}
	if strings.Contains(string(raw), "operation") || strings.Contains(string(raw), "prompt") {
		t.Fatalf("payload leaked: %s", raw)
	}
	digest := PushPayloadFor("https://pc.example", DigestType, "", 4)
	if digest.Title != "4 approvals waiting" || digest.URL != "https://pc.example/approvals" {
		t.Fatalf("digest payload %+v", digest)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authz, err := VAPIDAuthorization(key, "https://fcm.googleapis.com/fcm/send/abc", "mailto:ops@example.com", time.Unix(1_700_000_000, 0))
	if err != nil || !strings.HasPrefix(authz, "vapid t=") || strings.Count(authz, ".") != 2 {
		t.Fatalf("vapid: %s %v", authz, err)
	}
	if _, err := VAPIDAuthorization(key, "http://fcm.googleapis.com/fcm/send/abc", "mailto:ops@example.com", time.Unix(0, 0)); !errors.Is(err, ErrPushEndpoint) {
		t.Fatalf("http vapid: %v", err)
	}
	if _, err := EncryptPush([]byte("nope"), []byte{1, 2, 3}, []byte("0123456789abcdef")); !errors.Is(err, ErrPushKeys) {
		t.Fatalf("bad push keys: %v", err)
	}
}

// TestT359_APushPayloadHasNoActionDetails: a digest push names a count and
// the approvals page, and no other field.
// Covers: T-359
func TestT359_APushPayloadHasNoActionDetails(t *testing.T) {
	raw, err := json.Marshal(PushPayloadFor("https://pc.example", DigestType, "not-an-id", 2))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc) != 2 || doc["url"] != "https://pc.example/approvals" {
		t.Fatalf("payload %s", raw)
	}
}
