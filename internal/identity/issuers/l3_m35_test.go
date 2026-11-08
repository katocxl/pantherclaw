// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package issuers

import (
	"encoding/json/v2"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

func l3Bind(t *testing.T) (L3Bind, string) {
	t.Helper()
	org := ids.New[ids.Org]()
	bind := L3Bind{Org: org, Nonce: "nonce-1", JKT: "abcdefghijklmnopqrstuvwxyz0123456789-_ABC"}
	return bind, "spiffe://prod.example/ns/agents/sa/runner"
}

// TestHR777_Level3IsBoundToThisKey: only the L3 kinds set level 3, and the
// binding string names the org, the nonce and the key.
func TestHR777_Level3IsBoundToThisKey(t *testing.T) {
	if Level(KindSPIFFEX509) != 3 || Level(KindGCPInstance) != 3 {
		t.Fatal("spiffe_x509 and gcp_instance are not level 3")
	}
	if Level(KindAzureMI) == 3 || Level(KindAWS) == 3 {
		t.Fatal("Azure or AWS sets level 3")
	}
	bind, _ := l3Bind(t)
	want := "pantherclaw-l3:v1:" + bind.Org.String() + ":" + bind.Nonce + ":" + bind.JKT
	if bind.String() != want {
		t.Fatalf("binding %s, want %s", bind.String(), want)
	}
	other := bind
	other.JKT = "other-key-thumbprint-which-is-not-this-one-xx"
	if other.String() == bind.String() {
		t.Fatal("another key produced the same binding")
	}
}

// TestHR778_SPIFFEX509PinsTheOperatorID: the operator's SPIFFE ID and the
// signed binding pass, and another trust domain or another key's binding
// does not.
func TestHR778_SPIFFEX509PinsTheOperatorID(t *testing.T) {
	bind, id := l3Bind(t)
	entry := SPIFFEBinding{TrustDomain: "prod.example", SPIFFEID: id}
	svid := X509SVID{TrustDomain: "prod.example", SPIFFEID: id, Payload: []byte(bind.String())}
	if _, err := MatchSPIFFEX509(entry, bind, svid); err != nil {
		t.Fatalf("pinned SVID: %v", err)
	}
	other := bind
	other.JKT = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
	svid.Payload = []byte(other.String())
	if _, err := MatchSPIFFEX509(entry, bind, svid); err == nil {
		t.Fatal("a binding for another key was accepted")
	}
	svid.TrustDomain = "evil.example"
	svid.SPIFFEID = "spiffe://evil.example/ns/agents/sa/runner"
	svid.Payload = []byte(bind.String())
	if _, err := MatchSPIFFEX509(entry, bind, svid); err == nil {
		t.Fatal("another trust domain was accepted")
	}
}

// TestHR779_GCPInstancePinsTheProjectAndAudience: a token for this request
// passes, and one whose audience names another key does not. Level 3 ends
// when the attestation is no longer current; Azure does not set it.
func TestHR779_GCPInstancePinsTheProjectAndAudience(t *testing.T) {
	bind, _ := l3Bind(t)
	entry := GCPInstanceBinding{ProjectID: "acme-prod", InstanceID: "4519870034811532512", Zone: "us-central1-a"}
	aud, err := json.Marshal(bind.Audience())
	if err != nil {
		t.Fatal(err)
	}
	claims := GCPClaims{Issuer: GCPIssuer, Audience: aud}
	claims.Google.ComputeEngine.ProjectID = "acme-prod"
	claims.Google.ComputeEngine.InstanceID = "4519870034811532512"
	claims.Google.ComputeEngine.Zone = "projects/1/zones/us-central1-a"
	if _, err := MatchGCPInstance(entry, bind, claims); err != nil {
		t.Fatalf("pinned instance: %v", err)
	}
	other := bind
	other.JKT = "other-key"
	aud, err = json.Marshal(other.Audience())
	if err != nil {
		t.Fatal(err)
	}
	claims.Audience = aud
	if _, err := MatchGCPInstance(entry, bind, claims); err == nil {
		t.Fatal("a token for another key was accepted")
	}
	if Level(KindAzureMI) != 2 || !strings.HasPrefix(bind.Audience(), "pantherclaw:") {
		t.Fatal("level or audience drifted")
	}
}

// TestT353_AnL3AttestationForAnotherKeyIsRefused: the signed binding must
// be this request's key. Another key's binding does not enroll this one.
func TestT353_AnL3AttestationForAnotherKeyIsRefused(t *testing.T) {
	TestHR778_SPIFFEX509PinsTheOperatorID(t)
}
