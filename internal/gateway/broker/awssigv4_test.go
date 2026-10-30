// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package broker

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/credentials/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/egress"
	"github.com/katocxl/pantherclaw/internal/platform/sigv4"
	awssim "github.com/katocxl/pantherclaw/internal/sim/aws"
)

const awsBaseSecret = "simulated/base+secret0123456789"

type awsWorld struct {
	sim    *awssim.Server
	srv    *httptest.Server
	client *egress.Client
	cred   domain.AWSSigV4
	hosts  []string
}

// newAWS is a simulated account whose role may do anything in IAM and ECS:
// only the session policy narrows a session.
func newAWS(t *testing.T) *awsWorld {
	t.Helper()
	sim := awssim.New(awsBaseSecret, "", []string{"*"}, awssim.Faults{}, slog.New(slog.DiscardHandler))
	srv := httptest.NewServer(sim.Handler())
	t.Cleanup(srv.Close)
	c, err := egress.NewClient(srv.URL, 5*time.Second, 0, []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(srv.URL)
	return &awsWorld{sim: sim, srv: srv, client: c, hosts: []string{u.Host}, cred: domain.AWSSigV4{
		V: 1, AccessKeyID: awssim.BaseKeyID, SecretAccessKey: []byte(awsBaseSecret), RoleARN: awssim.RoleARN,
		STSURL: srv.URL, STSRegion: awssim.Region, Region: awssim.Region, Service: "iam",
	}}
}

// iam sends an aws-query IAM request signed by sess and returns the status.
func (w *awsWorld) iam(t *testing.T, sess *AWSSession, action string, extra url.Values) int {
	t.Helper()
	form := url.Values{"Action": {action}, "Version": {"2010-05-08"}, "RoleName": {awssim.RoleName}}
	for k, v := range extra {
		form[k] = v
	}
	body := []byte(form.Encode())
	u, _ := url.Parse(w.srv.URL + "/")
	req, err := w.client.HTTPRequest(t.Context(), egress.Request{Method: http.MethodPost, URL: u, Body: body, ContentType: "application/x-www-form-urlencoded; charset=utf-8"})
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Sign(req, body, time.Now()); err != nil {
		t.Fatal(err)
	}
	res, err := w.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res.Status
}

// TestHR525_EachDispatchAssumesANarrowedFifteenMinuteSession: AssumeRole
// asks for 900 seconds with a policy of exactly one action; the session can
// do that action and nothing else, though the role could; each dispatch
// gets its own session; the base key never signs a target request.
// Covers: HR-525, T-225
func TestHR525_EachDispatchAssumesANarrowedFifteenMinuteSession(t *testing.T) {
	w := newAWS(t)
	policy, err := SessionPolicy("iam", "GetRole", "*")
	if err != nil {
		t.Fatal(err)
	}
	if policy != `{"Statement":[{"Action":"iam:GetRole","Effect":"Allow","Resource":"*"}],"Version":"2012-10-17"}` {
		t.Fatalf("policy %s", policy)
	}
	now := time.Now()
	sess, err := AssumeRole(t.Context(), w.client, w.hosts, w.cred, policy, now)
	if err != nil {
		t.Fatal(err)
	}
	if d := sess.Expires().Sub(now); d > 15*time.Minute+maxSessionSkew || d <= 0 {
		t.Fatalf("session lasts %s", d)
	}
	if got := w.iam(t, sess, "GetRole", nil); got != http.StatusOK {
		t.Fatalf("GetRole: %d", got)
	}
	if got := w.iam(t, sess, "GetRolePolicy", url.Values{"PolicyName": {awssim.InlinePolicy}}); got != http.StatusForbidden {
		t.Fatalf("an action outside the session policy: %d", got)
	}
	second, err := AssumeRole(t.Context(), w.client, w.hosts, w.cred, policy, now)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(second.Secret(), sess.Secret()) || w.sim.Sessions() != 2 {
		t.Fatal("a session was reused")
	}
	sess.Clear()
	if strings.Trim(string(sess.Secret()), "\x00") != "" {
		t.Fatal("the session secret was not cleared")
	}
	for _, c := range w.sim.Calls() {
		if c.Key == "base" && c.Action != "AssumeRole" {
			t.Fatalf("the base key signed %s", c.Action)
		}
		if c.Key == "session" && (len(c.Policy) != 1 || c.Policy[0] != "iam:GetRole") {
			t.Fatalf("a session ran under %v", c.Policy)
		}
	}
	// The base key itself is refused at IAM: it may only assume the role.
	body := []byte("Action=GetRole&RoleName=" + awssim.RoleName + "&Version=2010-05-08")
	req, _ := w.client.HTTPRequest(t.Context(), egress.Request{Method: http.MethodPost, URL: mustURL(w.srv.URL + "/"), Body: body, ContentType: egress.FormContentType})
	if err := (sigv4.Signer{Region: awssim.Region, Service: "iam"}).Sign(req, sigv4.Credentials{AccessKeyID: awssim.BaseKeyID, SecretAccessKey: awsBaseSecret}, sigv4.HashPayload(body), time.Now()); err != nil {
		t.Fatal(err)
	}
	if res, err := w.client.Do(req); err != nil || res.Status != http.StatusForbidden {
		t.Fatalf("the base key at IAM: %d %v", res.Status, err)
	}
}

// TestHR525_ALongOrRefusedSessionIsNeverUsed: a session STS issued for
// longer than 15 minutes, a refused AssumeRole, an unbound STS host and an
// unbound target host all fail before anything is sent to the target.
// Covers: HR-525
func TestHR525_ALongOrRefusedSessionIsNeverUsed(t *testing.T) {
	w := newAWS(t)
	policy, _ := SessionPolicy("iam", "GetRole", "*")
	w.sim.SetFaults(awssim.Faults{LongSessions: true})
	if _, err := AssumeRole(t.Context(), w.client, w.hosts, w.cred, policy, time.Now()); !errors.Is(err, ErrAssumeRole) {
		t.Fatalf("an hour-long session: %v", err)
	}
	w.sim.SetFaults(awssim.Faults{DenyAssumeRole: true})
	if _, err := AssumeRole(t.Context(), w.client, w.hosts, w.cred, policy, time.Now()); !errors.Is(err, ErrAssumeRole) {
		t.Fatalf("a refused AssumeRole: %v", err)
	}
	w.sim.SetFaults(awssim.Faults{})
	n := len(w.sim.Calls())
	if _, err := AssumeRole(t.Context(), w.client, []string{"sts.amazonaws.com"}, w.cred, policy, time.Now()); !errors.Is(err, ErrNotBound) {
		t.Fatalf("an unbound STS host: %v", err)
	}
	if len(w.sim.Calls()) != n {
		t.Fatal("the base key reached an unbound host")
	}
	sess, err := AssumeRole(t.Context(), w.client, w.hosts, w.cred, policy, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, "https://iam.amazonaws.com/", nil)
	if err := sess.Sign(req, nil, time.Now()); !errors.Is(err, ErrNotBound) || req.Header.Get("Authorization") != "" {
		t.Fatalf("signed for an unbound host: %v", err)
	}
	req, _ = http.NewRequest(http.MethodPost, w.srv.URL+"/", nil)
	if err := sess.Sign(req, nil, time.Now().Add(time.Hour)); !errors.Is(err, ErrAssumeRole) {
		t.Fatalf("signed with an expired session: %v", err)
	}
	for _, bad := range [][2]string{{"iam", "Get*"}, {"iam", "GetRole,iam:*"}, {"IAM", "GetRole"}, {"iam", ""}} {
		if _, err := SessionPolicy(bad[0], bad[1], "*"); !errors.Is(err, ErrAWSAction) {
			t.Errorf("policy %v: %v", bad, err)
		}
	}
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

// TestT225_ASessionNarrowedToOneResourceReachesNoOther: a session whose
// policy names one role's ARN can read that role and no other, though the
// role it assumed may read every role; a wildcard resource is refused
// before AssumeRole.
// Covers: T-225, HR-525
func TestT225_ASessionNarrowedToOneResourceReachesNoOther(t *testing.T) {
	w := newAWS(t)
	policy, err := SessionPolicy("iam", "GetRole", awssim.RoleARN)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := AssumeRole(t.Context(), w.client, w.hosts, w.cred, policy, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got := w.iam(t, sess, "GetRole", nil); got != http.StatusOK {
		t.Fatalf("its own role: %d", got)
	}
	if got := w.iam(t, sess, "GetRole", url.Values{"RoleName": {"other-role"}}); got != http.StatusForbidden {
		t.Fatalf("another role: %d", got)
	}
	for _, r := range []string{"arn:aws:iam::" + awssim.Account + ":role/*", "arn:aws:iam::*:role/x", "role/x", ""} {
		if _, err := SessionPolicy("iam", "GetRole", r); !errors.Is(err, ErrAWSAction) {
			t.Errorf("resource %q: %v", r, err)
		}
	}
}
