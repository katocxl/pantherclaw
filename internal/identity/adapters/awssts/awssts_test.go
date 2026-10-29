// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package awssts_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/identity/adapters/awssts"
	"github.com/katocxl/pantherclaw/internal/identity/issuers"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

const result = `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:sts::123456789012:assumed-role/agent-runner/i-0abc</Arn>
    <UserId>AROAEXAMPLEID:i-0abc</UserId>
    <Account>123456789012</Account>
  </GetCallerIdentityResult>
  <ResponseMetadata><RequestId>01234567-89ab-cdef-0123-456789abcdef</RequestId></ResponseMetadata>
</GetCallerIdentityResponse>`

// sts is a fake STS endpoint reached for any host name, through a client
// that rewrites the destination (the request keeps its own URL).
type sts struct {
	srv  *httptest.Server
	got  *http.Request
	body string
	code int
	resp string
}

func newSTS(t *testing.T) *sts {
	t.Helper()
	s := &sts{code: http.StatusOK, resp: result}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s.got, s.body = r, string(b)
		w.WriteHeader(s.code)
		_, _ = w.Write([]byte(s.resp))
	}))
	t.Cleanup(s.srv.Close)
	return s
}

type rewrite struct{ to *url.URL }

func (rw rewrite) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.URL.Scheme, r.URL.Host = rw.to.Scheme, rw.to.Host
	return http.DefaultTransport.RoundTrip(r)
}

func (s *sts) client() *http.Client {
	u, _ := url.Parse(s.srv.URL)
	return &http.Client{Transport: rewrite{u}}
}

func token(t *testing.T, org ids.OrgID, host string, at time.Time) string {
	t.Helper()
	r := issuers.AWSRequest{
		Method: "POST", URL: "https://" + host + "/", Body: issuers.AWSBody,
		Headers: map[string]string{
			"content-type": "application/x-www-form-urlencoded; charset=utf-8", "host": host,
			"x-amz-date": at.UTC().Format("20060102T150405Z"), "x-pantherclaw-audience": "pantherclaw:" + org.String(),
			"authorization": "AWS4-HMAC-SHA256 Credential=ASIAEXAMPLEEXAMPLE12/" + at.UTC().Format("20060102") +
				"/us-east-1/sts/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-pantherclaw-audience, " +
				"Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7",
		},
	}
	tok, err := r.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// TestHR464_STSAnswersForCheckedRequestsOnly: a checked request is sent to
// STS exactly as signed and STS's answer is the caller; a request for an
// unlisted host, a refused signature or a non-result answer verifies
// nothing.
// Covers: PN-002.3
func TestHR464_STSAnswersForCheckedRequestsOnly(t *testing.T) {
	ctx := context.Background()
	org := ids.New[ids.Org]()
	now := time.Now()
	s := newSTS(t)
	v, err := awssts.New(s.client(), nil, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	c, signed, err := v.Verify(ctx, org, token(t, org, "sts.amazonaws.com", now))
	if err != nil {
		t.Fatal(err)
	}
	if c.Account != "123456789012" || c.Arn != "arn:aws:sts::123456789012:assumed-role/agent-runner/i-0abc" || signed.Signature == "" {
		t.Fatalf("caller = %+v %+v", c, signed)
	}
	if s.got.Method != http.MethodPost || s.got.Host != "sts.amazonaws.com" || s.body != issuers.AWSBody ||
		s.got.Header.Get("X-Pantherclaw-Audience") != "pantherclaw:"+org.String() || s.got.Header.Get("Authorization") == "" {
		t.Errorf("sent %s %s %q %v", s.got.Method, s.got.Host, s.body, s.got.Header)
	}
	if _, _, err := v.Verify(ctx, org, token(t, org, "sts.us-gov-west-1.amazonaws.com", now)); err != nil {
		t.Errorf("regional endpoint: %v", err)
	}

	for name, host := range map[string]string{
		"not sts":       "evil.test",
		"lookalike":     "sts.amazonaws.com.evil.test",
		"sub-subdomain": "x.sts.us-east-1.amazonaws.com",
	} {
		if _, _, err := v.Verify(ctx, org, token(t, org, host, now)); !errors.Is(err, issuers.ErrRejected) {
			t.Errorf("%s: %v", name, err)
		}
	}
	s.code, s.resp = http.StatusForbidden, `<ErrorResponse><Error><Code>SignatureDoesNotMatch</Code></Error></ErrorResponse>`
	if _, _, err := v.Verify(ctx, org, token(t, org, "sts.amazonaws.com", now)); !errors.Is(err, awssts.ErrUnverified) {
		t.Errorf("refused signature: %v", err)
	}
	s.code, s.resp = http.StatusOK, `<ErrorResponse/>`
	if _, _, err := v.Verify(ctx, org, token(t, org, "sts.amazonaws.com", now)); !errors.Is(err, awssts.ErrUnverified) {
		t.Errorf("not a result: %v", err)
	}

	pinned, err := awssts.New(s.client(), []string{"sts.eu-west-1.amazonaws.com"}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if pinned.Allowed("sts.amazonaws.com") || !pinned.Allowed("sts.eu-west-1.amazonaws.com") {
		t.Error("configured hosts replace the default")
	}
	for _, bad := range [][]string{{"STS.amazonaws.com"}, {"sts.amazonaws.com:443"}, {"https://sts.amazonaws.com"}, {""}} {
		if err := awssts.ValidateHosts(bad); err == nil {
			t.Errorf("hosts %q accepted", bad)
		}
	}
}
