// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package issuers_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/identity/issuers"
)

var awsNow = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

const awsSig = "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"

func awsRequest() issuers.AWSRequest {
	return issuers.AWSRequest{
		Method: "POST", URL: "https://sts.eu-west-1.amazonaws.com/", Body: issuers.AWSBody,
		Headers: map[string]string{
			"content-type": "application/x-www-form-urlencoded; charset=utf-8", "host": "sts.eu-west-1.amazonaws.com",
			"x-amz-date": "20261029T115500Z", "x-amz-security-token": "tok", "x-pantherclaw-audience": "pantherclaw:" + org.String(),
			"authorization": "AWS4-HMAC-SHA256 Credential=ASIAEXAMPLEEXAMPLE12/20261029/eu-west-1/sts/aws4_request, " +
				"SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-pantherclaw-audience, Signature=" + awsSig,
		},
	}
}

func stsHost(h string) bool { return h == "sts.eu-west-1.amazonaws.com" }

func TestAWSRequestRoundTrips(t *testing.T) {
	tok, err := awsRequest().Encode()
	if err != nil {
		t.Fatal(err)
	}
	r, err := issuers.ParseAWSRequest(tok)
	if err != nil {
		t.Fatal(err)
	}
	s, err := issuers.CheckAWSRequest(r, org, stsHost, awsNow)
	if err != nil {
		t.Fatal(err)
	}
	if s.Signature != awsSig || !s.SignedAt.Equal(awsNow.Add(-5*time.Minute)) || s.URL.String() != "https://sts.eu-west-1.amazonaws.com/" {
		t.Fatalf("signed = %+v", s)
	}
}

// TestHR464_AWSRequestRules: only POST GetCallerIdentity to an allowed STS
// host, only known headers, the audience header signed and exactly the
// org's, and signed within 15 minutes.
// Covers: PN-002.3
func TestHR464_AWSRequestRules(t *testing.T) {
	signed := "SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-pantherclaw-audience"
	for name, mutate := range map[string]func(*issuers.AWSRequest){
		"GET":                  func(r *issuers.AWSRequest) { r.Method = "GET" },
		"other action":         func(r *issuers.AWSRequest) { r.Body = "Action=AssumeRole&Version=2011-06-15" },
		"extra body":           func(r *issuers.AWSRequest) { r.Body += "&x=1" },
		"http":                 func(r *issuers.AWSRequest) { r.URL = "http://sts.eu-west-1.amazonaws.com/" },
		"unlisted host":        func(r *issuers.AWSRequest) { r.URL = "https://sts.evil.test/" },
		"port":                 func(r *issuers.AWSRequest) { r.URL = "https://sts.eu-west-1.amazonaws.com:8443/" },
		"query":                func(r *issuers.AWSRequest) { r.URL = "https://sts.eu-west-1.amazonaws.com/?Action=GetCallerIdentity" },
		"path":                 func(r *issuers.AWSRequest) { r.URL = "https://sts.eu-west-1.amazonaws.com/x" },
		"user info":            func(r *issuers.AWSRequest) { r.URL = "https://a@sts.eu-west-1.amazonaws.com/" },
		"host header mismatch": func(r *issuers.AWSRequest) { r.Headers["host"] = "sts.evil.test" },
		"unknown header":       func(r *issuers.AWSRequest) { r.Headers["x-forwarded-host"] = "evil.test" },
		"duplicate header":     func(r *issuers.AWSRequest) { r.Headers["X-Amz-Date"] = r.Headers["x-amz-date"] },
		"other org": func(r *issuers.AWSRequest) {
			r.Headers["x-pantherclaw-audience"] = "pantherclaw:00000000-0000-7000-8000-000000000000"
		},
		"no audience":           func(r *issuers.AWSRequest) { delete(r.Headers, "x-pantherclaw-audience") },
		"audience not signed":   replaceAuth(signed, "SignedHeaders=content-type;host;x-amz-date;x-amz-security-token"),
		"date not signed":       replaceAuth(signed, "SignedHeaders=content-type;host;x-amz-security-token;x-pantherclaw-audience"),
		"token not signed":      replaceAuth(signed, "SignedHeaders=content-type;host;x-amz-date;x-pantherclaw-audience"),
		"other service":         replaceAuth("/sts/aws4_request", "/iam/aws4_request"),
		"other algorithm":       replaceAuth("AWS4-HMAC-SHA256 ", "AWS4-ECDSA-P256-SHA256 "),
		"scope date mismatch":   replaceAuth("/20261029/", "/20261028/"),
		"signed 16 minutes ago": func(r *issuers.AWSRequest) { r.Headers["x-amz-date"] = "20261029T114400Z" },
		"signed in the future":  func(r *issuers.AWSRequest) { r.Headers["x-amz-date"] = "20261029T120500Z" },
		"bad date":              func(r *issuers.AWSRequest) { r.Headers["x-amz-date"] = "2026-10-29T11:55:00Z" },
		"no authorization":      func(r *issuers.AWSRequest) { delete(r.Headers, "authorization") },
	} {
		t.Run(name, func(t *testing.T) {
			r := awsRequest()
			mutate(&r)
			if _, err := issuers.CheckAWSRequest(r, org, stsHost, awsNow); !errors.Is(err, issuers.ErrRejected) {
				t.Fatalf("err = %v, want rejection", err)
			}
		})
	}
	if _, err := issuers.ParseAWSRequest("a.b.c"); !errors.Is(err, issuers.ErrRejected) {
		t.Errorf("a JWS parsed as an AWS request: %v", err)
	}
}

func replaceAuth(from, to string) func(*issuers.AWSRequest) {
	return func(r *issuers.AWSRequest) {
		r.Headers["authorization"] = strings.Replace(r.Headers["authorization"], from, to, 1)
	}
}

// TestHR464_AWSRoleSessionsOnly: the caller is a session of the pinned
// role in the pinned account; IAM users never match.
// Covers: PN-002.3
func TestHR464_AWSRoleSessionsOnly(t *testing.T) {
	b := issuers.AWSBinding{AccountID: "123456789012", RoleName: "agent-runner"}
	ok := issuers.AWSCaller{Account: "123456789012", Arn: "arn:aws:sts::123456789012:assumed-role/agent-runner/i-0abc"}
	m, err := issuers.MatchAWS(b, ok)
	if err != nil || !m.Binding.Equal(issuers.Binding{"account_id": "123456789012", "role_name": "agent-runner"}) {
		t.Fatalf("match = %+v, %v", m, err)
	}
	for name, c := range map[string]issuers.AWSCaller{
		"IAM user":       {Account: "123456789012", Arn: "arn:aws:iam::123456789012:user/agent-runner"},
		"other role":     {Account: "123456789012", Arn: "arn:aws:sts::123456789012:assumed-role/admin/i-0abc"},
		"role case":      {Account: "123456789012", Arn: "arn:aws:sts::123456789012:assumed-role/Agent-Runner/i-0abc"},
		"other account":  {Account: "210987654321", Arn: "arn:aws:sts::210987654321:assumed-role/agent-runner/i-0abc"},
		"account split":  {Account: "123456789012", Arn: "arn:aws:sts::210987654321:assumed-role/agent-runner/i-0abc"},
		"federated user": {Account: "123456789012", Arn: "arn:aws:sts::123456789012:federated-user/agent-runner"},
	} {
		if _, err := issuers.MatchAWS(b, c); !errors.Is(err, issuers.ErrRejected) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, b := range map[string]issuers.AWSBinding{
		"short account": {AccountID: "12345", RoleName: "r"},
		"role ARN":      {AccountID: "123456789012", RoleName: "arn:aws:iam::123456789012:role/r"},
		"role path":     {AccountID: "123456789012", RoleName: "team/r"},
	} {
		if err := b.Validate(); !errors.Is(err, issuers.ErrInvalidEntry) {
			t.Errorf("%s: Validate = %v", name, err)
		}
	}
}
