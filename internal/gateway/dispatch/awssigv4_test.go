// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/actionir"
	credentials "github.com/katocxl/pantherclaw/internal/credentials/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/gateway/broker"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	awssim "github.com/katocxl/pantherclaw/internal/sim/aws"
	pcaws "github.com/katocxl/pantherclaw/packages/pc-aws"
)

// TestHR525_TheDispatchSignsWithANarrowedSessionNeverTheBaseKey: an
// aws_sigv4 connection's request is signed by a session assumed for it and
// narrowed to the operation's one action; the base key never signs it; a
// target in another account, an operation that names no AWS action and a
// credential pattern are all refused before anything reaches IAM.
// Covers: HR-525, T-225
func TestHR525_TheDispatchSignsWithANarrowedSessionNeverTheBaseKey(t *testing.T) {
	const secret = "simulated/base+secret0123456789"
	sim := awssim.New(secret, "", []string{"*"}, awssim.Faults{}, slog.New(slog.DiscardHandler))
	srv := httptest.NewServer(sim.Handler())
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	plain, err := credentials.AWSSigV4{
		V: 1, AccessKeyID: awssim.BaseKeyID, SecretAccessKey: []byte(secret), RoleARN: awssim.RoleARN,
		STSURL: srv.URL, STSRegion: awssim.Region, Region: awssim.Region, Service: "iam",
	}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{
		broker: &plainOpener{plain: plain}, allowed: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
		tokenClients: map[string]clientEntry{}, log: pclog.Discard(),
	}
	conn := &control.Connection{GatewayConnection: &pb.GatewayConnection{Id: "c", BaseUrl: srv.URL}, Credential: &pb.SealedCredential{
		Kind: credentials.KindAWSSigV4, AllowedHosts: []string{u.Host}, Header: "Authorization", Scheme: "AWS4-HMAC-SHA256",
	}}
	p, err := manifest.Decode(pcaws.Package)
	if err != nil {
		t.Fatal(err)
	}
	def, _ := p.Definition("aws.iam.role.read")
	target := actionir.Target{Type: "aws_iam_role", ID: awssim.RoleName, Account: awssim.Account}
	body := []byte("Action=GetRole&RoleName=" + awssim.RoleName + "&Version=2010-05-08")
	newReq := func() *http.Request {
		r, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/", bytes.NewReader(body))
		r.Header.Set("Content-Type", defs.AWSQueryType)
		return r
	}
	req := newReq()
	sessionSecret, release, _, err := e.credential(context.Background(), conn, def, target, req, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	auth := req.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=ASIA") || strings.Contains(auth, awssim.BaseKeyID) ||
		req.Header.Get("X-Amz-Security-Token") == "" {
		t.Fatalf("signed %q", auth)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("GetRole: %v %v", res, err)
	}
	_ = res.Body.Close()
	release()
	if strings.Trim(string(sessionSecret), "\x00") != "" {
		t.Fatal("the session secret was not cleared")
	}
	calls := sim.Calls()
	if len(calls) != 2 || calls[0].Action != "AssumeRole" || calls[0].Key != "base" || calls[1].Key != "session" ||
		len(calls[1].Policy) != 1 || calls[1].Policy[0] != "iam:GetRole" {
		t.Fatalf("calls %+v", calls)
	}

	other := target
	other.Account = "999999999999"
	if _, _, _, err := e.credential(context.Background(), conn, def, other, newReq(), nil, ""); !errors.Is(err, errAWSAccount) {
		t.Fatalf("another account: %v", err)
	}
	noAction := &defs.Definition{Operation: "x.y", Target: defs.TargetSpec{Account: defs.PresenceNone}}
	if _, _, _, err := e.credential(context.Background(), conn, noAction, target, newReq(), nil, ""); !errors.Is(err, broker.ErrAWSAction) {
		t.Fatalf("no AWS action: %v", err)
	}
	patterned := *def
	d := *def.Dispatch
	d.CredentialPattern = "^.*$"
	patterned.Dispatch = &d
	if _, _, _, err := e.credential(context.Background(), conn, &patterned, target, newReq(), nil, ""); !errors.Is(err, ErrCredentialPattern) {
		t.Fatalf("a credential pattern: %v", err)
	}
	if len(sim.Calls()) != 2 {
		t.Fatal("a refused dispatch reached AWS")
	}
	if _, err := e.openStatic(context.Background(), conn); !errors.Is(err, errKind) {
		t.Fatalf("the base key was opened as a static credential: %v", err)
	}
}
