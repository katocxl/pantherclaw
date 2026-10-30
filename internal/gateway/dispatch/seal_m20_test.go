// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	"github.com/katocxl/pantherclaw/internal/actionir"
	credentials "github.com/katocxl/pantherclaw/internal/credentials/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/gateway/broker"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/pclaw"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/sim"
	awssim "github.com/katocxl/pantherclaw/internal/sim/aws"
	"github.com/katocxl/pantherclaw/internal/sim/teams"
	pcaws "github.com/katocxl/pantherclaw/packages/pc-aws"
	pcteams "github.com/katocxl/pantherclaw/packages/pc-teams"
)

const (
	sealOrg       = "0192aaaa-bbbb-7ccc-8ddd-000000000001"
	sealConn      = "0192aaaa-bbbb-7ccc-8ddd-000000000002"
	sealBrokerKey = "0192aaaa-bbbb-7ccc-8ddd-000000000003"
)

// sealedOpener opens a sealed credential the way the gateway's broker does:
// from the gateway's own view of its binding.
type sealedOpener struct{ key *pccrypto.SealPrivateKey }

func (o sealedOpener) Open(org, connection string, hosts []string, s broker.Sealed) ([]byte, error) {
	b := credentials.Binding{
		Org: org, Connection: connection, Version: s.Version, AllowedHosts: hosts, BrokerKey: s.BrokerKey,
		Header: s.Header, Scheme: s.Scheme, Kind: s.Kind,
	}
	return pccrypto.Open(o.key, b.Info(), credentials.AAD, s.Blob)
}

// sealingKeys serves GetSealingKey for one connection and keeps the upload.
type sealingKeys struct {
	pantherclawv1connect.UnimplementedConnectionServiceHandler
	key            *pccrypto.SealPrivateKey
	hosts          []string
	header, scheme string
	put            *pb.PutCredentialRequest
}

func (s *sealingKeys) GetSealingKey(_ context.Context, req *pb.GetSealingKeyRequest) (*pb.GetSealingKeyResponse, error) {
	pub := s.key.PublicKey().Bytes()
	sum := sha256.Sum256(pub)
	return &pb.GetSealingKeyResponse{
		OrgId: sealOrg, ConnectionId: req.GetConnectionId(), Version: 1, BrokerKeyId: sealBrokerKey, PublicKey: pub,
		Fingerprint: "sha256:" + hex.EncodeToString(sum[:]), GatewayId: "0192aaaa-bbbb-7ccc-8ddd-000000000004",
		AllowedHosts: s.hosts, Header: s.header, Scheme: s.scheme,
	}, nil
}

func (s *sealingKeys) PutCredential(_ context.Context, req *pb.PutCredentialRequest) (*pb.PutCredentialResponse, error) {
	s.put = req
	return &pb.PutCredentialResponse{Credential: &pb.ConnectionCredential{Version: req.GetVersion()}}, nil
}

// sealWithPclaw runs pclaw seal with secret on stdin against a stand-in
// control plane, and returns the engine and credential a gateway would then
// hold.
func sealWithPclaw(t *testing.T, hosts []string, header, scheme, secret string, flags ...string) (*Engine, *pb.SealedCredential) {
	t.Helper()
	key, err := pccrypto.GenerateSealKey()
	if err != nil {
		t.Fatal(err)
	}
	s := &sealingKeys{key: key, hosts: hosts, header: header, scheme: scheme}
	cs := connect.NewServer()
	pantherclawv1connect.RegisterConnectionServiceHandler(cs, s)
	mux := http.NewServeMux()
	connecthttp.Mount(mux, cs)
	api := httptest.NewServer(mux)
	t.Cleanup(api.Close)
	env := map[string]string{"PANTHERCLAW_SERVER": api.URL, "PANTHERCLAW_API_KEY": "pck_test_x"}
	var out, errs bytes.Buffer
	args := append([]string{"seal", "--connection", sealConn, "--from-file", "-"}, flags...)
	if code := pclaw.Run(context.Background(), args, &out, &errs, func(k string) (string, bool) { v, ok := env[k]; return v, ok },
		pclaw.Options{Stdin: strings.NewReader(secret + "\n")}); code != 0 || s.put == nil {
		t.Fatalf("seal = %d %q", code, errs.String())
	}
	if strings.Contains(out.String()+errs.String(), secret) || bytes.Contains(s.put.GetSealed(), []byte(secret)) {
		t.Fatal("the secret left the machine in plaintext")
	}
	e := &Engine{
		broker: sealedOpener{key: key}, org: sealOrg, allowed: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
		tokenClients: map[string]clientEntry{}, log: pclog.Discard(),
	}
	return e, &pb.SealedCredential{
		Version: s.put.GetVersion(), BrokerKeyId: s.put.GetBrokerKeyId(), Sealed: s.put.GetSealed(), Kind: s.put.GetKind(),
		AllowedHosts: s.put.GetAllowedHosts(), Header: s.put.GetHeader(), Scheme: s.put.GetScheme(),
	}
}

// TestHR524_ACredentialSealedByPclawPostsToTheTeamsSim: end to end from
// pclaw seal to a dispatch: the sealed oauth_client opens on the gateway,
// mints a token at the sim and posts to a channel (D280).
// Covers: HR-524, HR-060
func TestHR524_ACredentialSealedByPclawPostsToTheTeamsSim(t *testing.T) {
	const secret = "client~secret.not-real"
	s := teams.New(sim.TeamsChannels(), teams.Faults{}, slog.New(slog.DiscardHandler)).
		WithRequire(teams.Require{ClientID: teams.AppID, ClientSecret: secret})
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	e, cred := sealWithPclaw(t, []string{u.Host}, "Authorization", "Bearer", secret,
		"--oauth-token-url", srv.URL+"/"+teams.TenantID+"/oauth2/v2.0/token", "--oauth-client-id", teams.AppID, "--oauth-scope", teams.Scope)
	p, err := manifest.Decode(pcteams.Package)
	if err != nil {
		t.Fatal(err)
	}
	def, _ := p.Definition("teams.message.post")
	conn := &control.Connection{
		GatewayConnection: &pb.GatewayConnection{Id: sealConn, Kind: "http", BaseUrl: srv.URL + "/teams"}, Package: p, Credential: cred,
	}
	body := fmt.Sprintf(`{"isGroup":true,"channelData":{"channel":{"id":%q},"tenant":{"id":%q}},"activity":{"type":"message","text":"hello"}}`,
		sim.TeamsGeneral, teams.TenantID)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/teams/v3/conversations", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	target := actionir.Target{Type: "teams_channel", ID: sim.TeamsGeneral, Account: teams.TenantID}
	_, release, _, err := e.credential(context.Background(), conn, def, target, req, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusCreated || len(s.Messages()) != 1 || s.Messages()[0].Text != "hello" || s.Issued() != 1 {
		t.Fatalf("post: %d %s, %d messages, %d tokens", res.StatusCode, raw, len(s.Messages()), s.Issued())
	}
}

// TestHR525_ACredentialSealedByPclawCallsTheAWSSim: end to end from pclaw
// seal to a dispatch: the sealed aws_sigv4 opens on the gateway, assumes a
// narrowed session at the sim and reads the role with it (D280).
// Covers: HR-525, HR-060
func TestHR525_ACredentialSealedByPclawCallsTheAWSSim(t *testing.T) {
	const secret = "simulated/base+secret0123456789"
	s := awssim.New(secret, "", []string{"*"}, awssim.Faults{}, slog.New(slog.DiscardHandler))
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	e, cred := sealWithPclaw(t, []string{u.Host}, "Authorization", credentials.AWSSigV4Scheme, secret,
		"--aws-access-key-id", awssim.BaseKeyID, "--aws-role-arn", awssim.RoleARN, "--aws-sts-url", srv.URL,
		"--aws-sts-region", awssim.Region, "--aws-region", awssim.Region, "--aws-service", "iam")
	p, err := manifest.Decode(pcaws.Package)
	if err != nil {
		t.Fatal(err)
	}
	def, _ := p.Definition("aws.iam.role.read")
	conn := &control.Connection{GatewayConnection: &pb.GatewayConnection{Id: sealConn, BaseUrl: srv.URL}, Credential: cred}
	body := []byte("Action=GetRole&RoleName=" + awssim.RoleName + "&Version=2010-05-08")
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL+"/", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", defs.AWSQueryType)
	target := actionir.Target{Type: "aws_iam_role", ID: awssim.RoleName, Account: awssim.Account}
	_, release, _, err := e.credential(context.Background(), conn, def, target, req, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GetRole: %d", res.StatusCode)
	}
	calls := s.Calls()
	if len(calls) != 2 || calls[0].Action != "AssumeRole" || calls[1].Key != "session" || len(calls[1].Policy) != 1 || calls[1].Policy[0] != "iam:GetRole" {
		t.Fatalf("calls %+v", calls)
	}
}
