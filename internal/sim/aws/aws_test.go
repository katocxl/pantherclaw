// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package aws

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/sigv4"
)

const secret = "simulated/base+secret0123456789"

func signed(t *testing.T, srv *httptest.Server, service string, creds sigv4.Credentials, form url.Values, now time.Time) *http.Request {
	t.Helper()
	body := form.Encode()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	if err := (sigv4.Signer{Region: Region, Service: service}).Sign(req, creds, sigv4.HashPayload([]byte(body)), now); err != nil {
		t.Fatal(err)
	}
	return req
}

func do(t *testing.T, req *http.Request) (int, string) {
	t.Helper()
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

func TestAWSSimVerifiesSignaturesAndSessions(t *testing.T) {
	s := New(secret, "ext-1", []string{"iam:GetRole"}, Faults{}, slog.New(slog.DiscardHandler))
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	base := sigv4.Credentials{AccessKeyID: BaseKeyID, SecretAccessKey: secret}
	policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"}]}`
	assume := url.Values{
		"Action": {"AssumeRole"}, "Version": {"2011-06-15"}, "RoleArn": {RoleARN}, "RoleSessionName": {"t"},
		"DurationSeconds": {"900"}, "Policy": {policy},
	}
	if code, _ := do(t, signed(t, srv, "sts", base, assume, time.Now())); code != http.StatusForbidden {
		t.Fatalf("no external id: %d", code)
	}
	assume.Set("ExternalId", "ext-1")
	bad := signed(t, srv, "sts", sigv4.Credentials{AccessKeyID: BaseKeyID, SecretAccessKey: "wrong-" + "secret-0123456789"}, assume, time.Now())
	if code, body := do(t, bad); code != http.StatusForbidden || !strings.Contains(body, "SignatureDoesNotMatch") {
		t.Fatalf("wrong secret: %d %s", code, body)
	}
	code, body := do(t, signed(t, srv, "sts", base, assume, time.Now()))
	if code != http.StatusOK {
		t.Fatalf("AssumeRole: %d %s", code, body)
	}
	field := func(name string) string {
		return regexp.MustCompile(`<` + name + `>([^<]*)</` + name + `>`).FindStringSubmatch(body)[1]
	}
	sess := sigv4.Credentials{AccessKeyID: field("AccessKeyId"), SecretAccessKey: field("SecretAccessKey"), SessionToken: field("SessionToken")}
	getRole := url.Values{"Action": {"GetRole"}, "Version": {"2010-05-08"}, "RoleName": {RoleName}}
	if code, _ := do(t, signed(t, srv, "iam", sess, getRole, time.Now())); code != http.StatusOK {
		t.Fatalf("GetRole: %d", code)
	}
	// The session policy allows iam:*, but the role allows only GetRole.
	list := url.Values{"Action": {"ListAttachedRolePolicies"}, "Version": {"2010-05-08"}, "RoleName": {RoleName}}
	if code, _ := do(t, signed(t, srv, "iam", sess, list, time.Now())); code != http.StatusForbidden {
		t.Fatalf("outside the role: %d", code)
	}
	tampered := signed(t, srv, "iam", sess, getRole, time.Now())
	tampered.Body = io.NopCloser(strings.NewReader("Action=GetRole&RoleName=other&Version=2010-05-08"))
	tampered.ContentLength = -1
	if code, _ := do(t, tampered); code != http.StatusForbidden {
		t.Fatalf("tampered body: %d", code)
	}
	later := time.Now().Add(20 * time.Minute)
	s.SetClock(func() time.Time { return later })
	if code, body := do(t, signed(t, srv, "iam", sess, getRole, later)); code != http.StatusForbidden || !strings.Contains(body, "ExpiredToken") {
		t.Fatalf("expired session: %d %s", code, body)
	}
}
