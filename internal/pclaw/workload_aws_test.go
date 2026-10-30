// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/identity/issuers"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// TestSigV4SigningKey is the signing-key example of the AWS SigV4
// documentation.
func TestSigV4SigningKey(t *testing.T) {
	got := hex.EncodeToString(awsSigningKey("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20120215", "us-east-1", "iam"))
	if got != "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d" {
		t.Fatalf("signing key = %s", got)
	}
}

// TestAWSAttestationPassesTheServerChecks: --aws produces a request the
// server's AWS rules accept, signing the audience, date, host and session
// token, on the regional endpoint when a region is set.
// Covers: PN-002.3
func TestAWSAttestationPassesTheServerChecks(t *testing.T) {
	org := ids.New[ids.Org]()
	now := time.Now()
	sts := func(h string) bool { return h == "sts.amazonaws.com" || h == "sts.eu-west-1.amazonaws.com" }
	for region, host := range map[string]string{"": "sts.amazonaws.com", "eu-west-1": "sts.eu-west-1.amazonaws.com"} {
		c := awsCredentials{accessKey: "ASIAEXAMPLEEXAMPLE12", secretKey: "secret", sessionToken: "session token", region: region}
		tok, err := awsAttestation(c, "pantherclaw:"+org.String(), now)
		if err != nil {
			t.Fatal(err)
		}
		r, err := issuers.ParseAWSRequest(tok)
		if err != nil {
			t.Fatal(err)
		}
		s, err := issuers.CheckAWSRequest(r, org, sts, now)
		if err != nil {
			t.Fatalf("region %q: %v", region, err)
		}
		if s.URL.Host != host || !strings.Contains(r.Header("Authorization"),
			"SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-pantherclaw-audience,") {
			t.Errorf("region %q: %s %s", region, s.URL, r.Header("Authorization"))
		}
		if strings.Contains(tok, "secret") {
			t.Error("the secret key is in the attestation")
		}
	}
	if _, err := awsFromEnv(&app{env: envOf(map[string]string{"AWS_ACCESS_KEY_ID": "AKIA"})}); err == nil {
		t.Error("credentials without a secret key")
	}
}
